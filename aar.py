#
# Copyright 2023 Canonical Ltd.  All rights reserved.
#

import os
import netifaces
from jinja2 import Environment, FileSystemLoader
from pathlib import Path
import ops
from helpers import pki
from lib.charms.operator_libs_linux.v2 import snap

SNAP_NAME = "aar"
SNAP_COMMON_PATH = Path("/var/snap/aar/common")
AAR_CONFIG_PATH = SNAP_COMMON_PATH  / "conf/main.yaml"

AAR_CERT_BASE_PATH =  SNAP_COMMON_PATH / "certs"

AAR_SERVER_CERT_PATH = AAR_CERT_BASE_PATH / "server.crt"
AAR_SERVER_KEY_PATH = AAR_CERT_BASE_PATH / "server.key"

CLIENTS_CERT_PATH = AAR_CERT_BASE_PATH / "clients"
PUBLISHERS_CERT_PATH = AAR_CERT_BASE_PATH / "publishers"

class AAR:

    def __init__(self, charm: ops.CharmBase):
        self._sc = snap.SnapCache()
        self._charm = charm

    def restart(self):
        self._sc['aar'].restart()

    def remove(self):
        self._sc['aar']._remove()

    def install(self):
        try:
            res = self._charm.model.resources.fetch("aar-snap")
        except ops.ModelError:
            res = None

        # FIXME: Install the aar snap from a resource until we make the
        # snaps in the snap store unlisted
        if res is not None and res.stat().st_size:
            snap.install_local(res, classic=False, dangerous=True)
        else:
            self._charm.unit.status = ops.BlockedStatus("cannot install aar: snap resource not found")
            return

        aar_snap = self._sc["aar"]
        aar_snap.connect(plug="home", slot=":home")
        aar_snap.connect(plug="network", slot=":network")

    @property
    def version(self) -> str:
        snaps = self._sc._snap_client.get_installed_snaps()
        for installed_snap in snaps:
            if installed_snap["name"] == SNAP_NAME:
                return installed_snap["version"]
        return ""

    @property
    def installed(self) -> bool:
        snaps = self._sc._snap_client.get_installed_snaps()
        for installed_snap in snaps:
            if installed_snap["name"] == SNAP_NAME:
                return True
        return False

    @staticmethod
    def get_ip_for_interface(interface):
        """Return the ip address associated to the given interface."""
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addresses or "addr" not in addresses[netifaces.AF_INET][0]:
            raise Exception("No IP associated to requested device")
        return addresses[netifaces.AF_INET][0]["addr"]

    def configure(self,
          port: ops.Port,
          storage_config: str,
          listen_address: str,
          ingress_address: str,
    ):
        tenv = Environment(loader=FileSystemLoader("templates"))
        template = tenv.get_template("config.yaml.j2")
        rendered_content = template.render(
            {
                "listen_address": f"{listen_address}:{port.port}",
                "storage_config": storage_config,
            }
        )
        AAR_CONFIG_PATH.write_text(rendered_content)
        self._setup_certs(ingress_address, ingress_address, listen_address)

    def _setup_certs(self, hostname: str, public_ip: str, private_ip: str):
        os.makedirs(CLIENTS_CERT_PATH, 0o700, exist_ok=True)
        os.makedirs(PUBLISHERS_CERT_PATH, 0o700, exist_ok=True)
        pki.create_cert_files_if_needed(
            cert_path=AAR_SERVER_CERT_PATH,
            key_path=AAR_SERVER_KEY_PATH,
            hostname=hostname,
            public_ip=public_ip,
            private_ip=private_ip,
        )

