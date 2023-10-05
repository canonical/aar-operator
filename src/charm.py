#!/usr/bin/env python3
#
# Anbox - The Android in a Box runtime environment
# Copyright 2019 Canonical Ltd.  All rights reserved.
#

"""Charmed Machine Operator For Anbox Application Registry (AAR)."""

import ipaddress
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from subprocess import STDOUT, CalledProcessError, check_output

import netifaces
import ops
from charms.operator_libs_linux.v1 import systemd
from charms.operator_libs_linux.v2 import snap
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.client_relation_joined, self._on_aar_joined)
        self.framework.observe(self.on.publisher_relation_joined, self._on_aar_joined)

        self.framework.observe(self.on.client_relation_changed, self._on_aar_changed)
        self.framework.observe(self.on.publisher_relation_changed, self._on_aar_changed)

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
        unit_data["fingerprint"] = self._get_fingerprint(cert)
        unit_data["ip"] = listen_address
        unit_data["port"] = str(self.config.get("port", ""))

    def _get_fingerprint(self, cert: str) -> str:
        x509_cert = x509.load_pem_x509_certificate(cert.encode())
        return x509_cert.fingerprint(hashes.SHA256()).hex()

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

    def _on_aar_changed(self, event: ops.RelationChangedEvent):
        self.unit.status = ops.MaintenanceStatus("Confguring new AMS Client")
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
            self._register_ams_client(client["certificate"], event.relation.name)
            logger.info(f"client registered {client['certificate']}")

        aar_snap = snap.SnapCache()["aar"]
        aar_snap.restart()
        self.unit.status = ops.ActiveStatus()

    def _register_ams_client(self, client_certificate: str, mode: str):
        try:
            client_certificate = client_certificate.replace("\\n", "\n").strip('"')
            cmd = ["/snap/bin/aar", "trust", "add"]
            if mode == "publisher":
                cmd.append("--publisher")
            check_output(cmd, stderr=STDOUT, input=client_certificate.encode("utf-8"))
        except CalledProcessError as ex:
            logger.error(f"failed to add client to aar: {ex.output}")
            raise

    def _snap_installed(self, snap_name) -> bool:
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

    def _create_cert_files_if_needed(self, cert_path, key_path):
        if os.path.exists(cert_path) and os.path.exists(key_path):
            return

        cert, key = self._generate_selfsigned_cert(self.public_ip, self.public_ip, self.private_ip)

        cert_base_path = os.path.dirname(cert_path)
        if not os.path.exists(cert_base_path):
            os.makedirs(cert_base_path, mode=0o0700)

        key_base_path = os.path.dirname(key_path)
        if not os.path.exists(key_base_path):
            os.makedirs(key_base_path, mode=0o0700)

        with open(os.open(cert_path, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
            f.write(str(cert, "UTF-8"))

        with open(os.open(key_path, os.O_CREAT | os.O_WRONLY, 0o600), "w") as f:
            f.write(str(key, "UTF-8"))

    def _generate_selfsigned_cert(self, hostname, public_ip, private_ip):
        if not hostname:
            raise Exception("A hostname is required")

        if not public_ip:
            raise Exception("A public IP is required")

        if not private_ip:
            raise Exception("A private IP is required")

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=4096, backend=default_backend()
        )

        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname)])
        alt_names = x509.SubjectAlternativeName(
            [
                # best practice seem to be to include the hostname in the SAN
                x509.DNSName(hostname),
                # allow addressing by IP, for when you don't have real DNS
                # openssl wants DNSnames for ips...
                x509.DNSName(public_ip),
                x509.DNSName(private_ip),
                x509.IPAddress(ipaddress.IPv4Address(public_ip)),
                x509.IPAddress(ipaddress.IPv4Address(private_ip)),
            ]
        )
        # path_len=0 means this cert can only sign itself, not other certs.
        basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1000)
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=10 * 365))
            .add_extension(basic_contraints, False)
            .add_extension(alt_names, False)
            .sign(key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem

    def _on_install(self, event: ops.InstallEvent):
        if not self._snap_installed(SNAP_NAME):
            self.unit.status = ops.MaintenanceStatus("installing aar")
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

        os.makedirs(CLIENT_CERT_PATH, 0o700, exist_ok=True)
        os.makedirs(PUBLISHERS_CERT_PATH, 0o700, exist_ok=True)
        self._create_cert_files_if_needed(AAR_SERVER_CERT_PATH, AAR_SERVER_KEY_PATH)

        version = self._get_snap_version(SNAP_NAME)
        self.unit.set_workload_version(version)
        self.unit.status = ops.ActiveStatus()

    def _get_snap_version(self, snap_name: str) -> str:
        snap_client = snap.SnapClient()
        snaps = snap_client.get_installed_snaps()
        for installed_snap in snaps:
            if installed_snap["name"] == snap_name:
                return installed_snap["version"]
        return ""

    def _on_config_changed(self, event: ops.ConfigChangedEvent):
        if not self._snap_installed(SNAP_NAME):
            self._on_install(event)
            return
        port = ops.Port(protocol="tcp", port=int(self.config["port"]))
        listen_address = self.private_ip
        tenv = Environment(loader=FileSystemLoader("templates"))
        template = tenv.get_template("config.yaml.j2")
        rendered_content = template.render(
            {
                "listen_address": f"{listen_address}:{port.port}",
                "storage_config": self.config["storage_config"],
            }
        )
        AAR_CONFIG_PATH.write_text(rendered_content)
        self.unit.set_ports(port)
        systemd.service_restart(SERVICE)

        self.unit.status = ops.ActiveStatus()


if __name__ == "__main__":
    ops.main(AARCharm)
