#!/usr/bin/env python3
#
# Anbox - The Android in a Box runtime environment
# Copyright 2019 Canonical Ltd.  All rights reserved.
#

"""Charmed Machine Operator For Anbox Application Registry (AAR)."""

import logging
import os
import shutil
from pathlib import Path
from subprocess import STDOUT, CalledProcessError, check_output

import netifaces
import ops
from nrpe.client import NRPEClient  # noqa: E402
from lib.charms.operator_libs_linux.v2 import snap
from helpers import pki
from jinja2 import Environment, FileSystemLoader


logger = logging.getLogger(__name__)

SERVICE = "snap.aar.daemon.service"
UA_STATUS_PATH = "/var/lib/ubuntu-advantage/status.json"
SNAP_COMMON_PATH = Path("/var/snap/aar/common")
AAR_CONFIG_PATH = SNAP_COMMON_PATH / "conf/main.yaml"
SNAP_NAME = "aar"

AAR_CERT_BASE_PATH = SNAP_COMMON_PATH / "certs"
CLIENT_CERT_PATH = AAR_CERT_BASE_PATH / "clients"
PUBLISHERS_CERT_PATH = AAR_CERT_BASE_PATH / "publishers"
AAR_SERVER_CERT_PATH = AAR_CERT_BASE_PATH / "server.crt"
AAR_SERVER_KEY_PATH = AAR_CERT_BASE_PATH / "server.key"


class AARCharm(ops.CharmBase):
    """Charmed Operator to deploy AAR - Anbox Application Registry."""

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.stop, self._on_stop)
        self.framework.observe(self.on.client_relation_joined, self._on_aar_joined)
        self.framework.observe(self.on.publisher_relation_joined, self._on_aar_joined)

        self.framework.observe(self.on.client_relation_changed, self._on_aar_changed)
        self.framework.observe(self.on.publisher_relation_changed, self._on_aar_changed)
        self.nrpe_client = NRPEClient(self, "nrpe-external-master")
        self.framework.observe(self.nrpe_client.on.nrpe_available, self._on_nrpe_available)

    @property
    def public_ip(self) -> str:
        """Public address of the unit."""
        public_iface = self.config["public_interface"]
        if public_iface:
            public_address = self._get_ip_for_interface(public_iface)
            if public_address:
                return public_address
            logger.warning(
                "Could not obtain a valid IP for the configured public_interface. \
                Using the default one"
            )
        return self.model.get_binding("juju-info").network.ingress_address.exploded

    @property
    def private_ip(self) -> str:
        """Private address of the unit."""
        return self.model.get_binding("juju-info").network.bind_address.exploded

    def _install_snap(self):
        try:
            res = self.model.resources.fetch("aar-snap")
        except ops.ModelError:
            res = None

        # FIXME: Install the aar snap from a resource until we make the
        # snaps in the snap store unlisted
        if res is not None and res.stat().st_size:
            snap.install_local(res, classic=False, dangerous=True)
        else:
            self.unit.status = ops.BlockedStatus("cannot install aar: snap resource not found")
            return

        aar_snap = snap.SnapCache()["aar"]
        aar_snap.connect(plug="home", slot=":home")
        aar_snap.connect(plug="network", slot=":network")

    def _setup_certs(self):
        os.makedirs(CLIENT_CERT_PATH, 0o700, exist_ok=True)
        os.makedirs(PUBLISHERS_CERT_PATH, 0o700, exist_ok=True)
        pki.create_cert_files_if_needed(
            cert_path=AAR_SERVER_CERT_PATH,
            key_path=AAR_SERVER_KEY_PATH,
            hostname=self.public_ip,
            public_ip=self.public_ip,
            private_ip=self.private_ip
        )

    def _on_config_changed(self, event: ops.ConfigChangedEvent):
        self.unit.status = ops.MaintenanceStatus("Configuring AAR")
        if not self._is_snap_installed(SNAP_NAME):
            self.unit.status = ops.MaintenanceStatus("Installing AAR")
            self._install_snap()
            self._setup_certs()

        port = ops.Port(protocol="tcp", port=int(self.config["port"]))
        self._set_aar_config(port, self.private_ip)
        self.unit.set_ports(port)

        self._on_nrpe_available(event)

        aar_snap = snap.SnapCache()['aar']
        aar_snap.restart()

        version = self._get_snap_version(SNAP_NAME)
        self.unit.set_workload_version(version)

        self.unit.status = ops.ActiveStatus()

    def _set_aar_config(self, port: ops.Port, listen_address: str):
        tenv = Environment(loader=FileSystemLoader("templates"))
        template = tenv.get_template("config.yaml.j2")
        rendered_content = template.render(
            {
                "listen_address": f"{listen_address}:{port.port}",
                "storage_config": self.config["storage_config"],
            }
        )
        AAR_CONFIG_PATH.write_text(rendered_content)

    def _on_stop(self, _: ops.StopEvent):
        snap.remove('aar')

    def _on_aar_joined(self, event: ops.RelationJoinedEvent):
        with open(AAR_SERVER_CERT_PATH, "r") as f:
            cert = f.read()
        if not cert:
            self.unit.status = ops.BlockedStatus("No registry certificate")
            return

        listen_address = self.private_ip
        location = self.config.get("location")
        if location:
            listen_address = location

        unit_data = event.relation.data[self.unit]
        unit_data["certificate"] = cert
        unit_data["fingerprint"] = pki.get_fingerprint(cert)
        unit_data["ip"] = listen_address
        unit_data["port"] = str(self.config.get("port", ""))

    def _on_aar_changed(self, event: ops.RelationChangedEvent):
        self.unit.status = ops.MaintenanceStatus("Confguring new AAR Client")
        self._remove_all_certificates()
        ams_clients = []
        for unit in event.relation.units:
            cert = event.relation.data[unit].get("certificate")
            if not cert:
                continue

            # If there is a relation mismatch, we set an error status
            # ex: juju add-relation aar:client ams:publisher
            mode = event.relation.data[unit]["mode"].strip('"')
            if mode not in event.relation.name:
                self.unit.status = ops.BlockedStatus(
                    "Invalid relation {} to {}".format("arr-" + mode, event.relation.name)
                )
                return
            ams_clients.append(event.relation.data[unit])

        if not ams_clients:
            return
        for client in ams_clients:
            try:
                self._register_aar_client(client["certificate"], event.relation.name)
                logger.info(f"new client registered")
            except CalledProcessError as ex:
                logger.error(f"failed to add client to aar: {ex.output}")
                self.unit.status = ops.BlockedStatus('Failed to register client certificate')
                return

        aar_snap = snap.SnapCache()["aar"]
        aar_snap.restart()
        self.unit.status = ops.ActiveStatus()

    def _on_nrpe_available(self, _):
        if self.nrpe_client.is_available:
            check_name = "check_{}".format(self.model.unit.name.replace("/", "_"))
            self.nrpe_client.add_check(
                command=[
                    '/usr/lib/nagios/plugins/check_http',
                    '--ssl', '--hostname', "{}:{}".format(self.private_ip, self.config["port"]),
                    '--url', '/1.0/status', '--expect', '200',
                    '--warning', '5', '--critical', '10'
                ],
                name=check_name,
            )
            self.nrpe_client.commit()

    def _remove_all_certificates(self):
        """Remove all old certificates held by AAR.

        All client certificates are kept by juju in the relation until the hook
        fails, so every time a new client is registered, the previous certificates
        will be added again. To avoid duplicates and properly take into account
        units that departed, we remove all certificates and add the ones that
        are still active again.
        """
        shutil.rmtree(CLIENT_CERT_PATH)
        shutil.rmtree(PUBLISHERS_CERT_PATH)
        os.makedirs(CLIENT_CERT_PATH, 0o700, exist_ok=True)
        os.makedirs(PUBLISHERS_CERT_PATH, 0o700, exist_ok=True)

    def _register_aar_client(self, client_certificate: str, mode: str):
        client_certificate = client_certificate.replace("\\n", "\n").strip('"')
        cmd = ["/snap/bin/aar", "trust", "add"]
        if mode == "publisher":
            cmd.append("--publisher")
        check_output(cmd, stderr=STDOUT, input=client_certificate.encode("utf-8"))

    def _is_snap_installed(self, snap_name) -> bool:
        snap_client = snap.SnapClient()
        snaps = snap_client.get_installed_snaps()
        for installed_snap in snaps:
            if installed_snap["name"] == snap_name:
                return True
        return False

    def _get_ip_for_interface(self, interface):
        """Return the ip address associated to the given interface."""
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addresses or "addr" not in addresses[netifaces.AF_INET][0]:
            raise Exception("No IP associated to requested device")

        return addresses[netifaces.AF_INET][0]["addr"]

    def _get_snap_version(self, snap_name: str) -> str:
        snap_client = snap.SnapClient()
        snaps = snap_client.get_installed_snaps()
        for installed_snap in snaps:
            if installed_snap["name"] == snap_name:
                return installed_snap["version"]
        return ""

if __name__ == "__main__":
    ops.main(AARCharm)
