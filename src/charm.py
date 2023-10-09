#!/usr/bin/env python3
#
# Anbox - The Android in a Box runtime environment
# Copyright 2023 Canonical Ltd.  All rights reserved.
#

"""Charmed Machine Operator For Anbox Application Registry (AAR)."""

import logging
import os

import netifaces
import ops
from helpers import pki
from jinja2 import Environment, FileSystemLoader

from constants import (
    AAR_CONFIG_PATH,
    AAR_SERVER_CERT_PATH,
    AAR_SERVER_KEY_PATH,
    CLIENTS_CERT_PATH,
    PUBLISHERS_CERT_PATH,
)
from interfaces import AAREndpointProvider, ClientRegisteredEvent
from snap import AARSnap

logger = logging.getLogger(__name__)


class AARCharm(ops.CharmBase):
    """Charmed Operator to deploy AAR - Anbox Application Registry."""

    def __init__(self, *args):
        super().__init__(*args)
        self._snap = AARSnap(self)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self.framework.observe(self.on.stop, self._on_stop)

        self._client = AAREndpointProvider(self, "client")
        self.framework.observe(self._client.on.client_registered, self._on_aar_client_registered)

        self._publisher = AAREndpointProvider(self, "publisher")
        self.framework.observe(
            self._publisher.on.client_registered, self._on_aar_client_registered
        )

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

    def _on_config_changed(self, _: ops.ConfigChangedEvent):
        self.unit.status = ops.MaintenanceStatus("Configuring AAR")
        if not self._snap.installed:
            self.unit.status = ops.MaintenanceStatus("Installing AAR")
            self._snap.install()
            self._setup_certs()

        port = ops.Port(protocol="tcp", port=int(self.config["port"]))
        self._set_aar_config(port, self.private_ip)
        self.unit.set_ports(port)

        self.unit.set_workload_version(self._snap.version)
        self._snap.restart()
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
        self._snap.remove()

    def _on_aar_client_registered(self, _: ClientRegisteredEvent):
        self._snap.restart()
        self.unit.status = ops.ActiveStatus()

    def _get_ip_for_interface(self, interface):
        """Return the ip address associated to the given interface."""
        addresses = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addresses or "addr" not in addresses[netifaces.AF_INET][0]:
            raise Exception("No IP associated to requested device")

        return addresses[netifaces.AF_INET][0]["addr"]

    def _setup_certs(self):
        os.makedirs(CLIENTS_CERT_PATH, 0o700, exist_ok=True)
        os.makedirs(PUBLISHERS_CERT_PATH, 0o700, exist_ok=True)
        pki.create_cert_files_if_needed(
            cert_path=AAR_SERVER_CERT_PATH,
            key_path=AAR_SERVER_KEY_PATH,
            hostname=self.public_ip,
            public_ip=self.public_ip,
            private_ip=self.private_ip,
        )


if __name__ == "__main__":
    ops.main(AARCharm)
