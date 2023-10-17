#!/usr/bin/env python3
#
# Copyright 2023 Canonical Ltd.  All rights reserved.
#

"""Charmed Machine Operator For Anbox Application Registry (AAR)."""

import logging

import ops

from aar import AAR
from interfaces import AAREndpointProvider, ClientRegisteredEvent

logger = logging.getLogger(__name__)


class AARCharm(ops.CharmBase):
    """Charmed Operator to deploy AAR - Anbox Application Registry."""

    def __init__(self, *args):
        super().__init__(*args)
        self._snap = AAR(self)
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
            public_address = AAR.get_ip_for_interface(public_iface)
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
        if not self._snap.installed:
            self.unit.status = ops.MaintenanceStatus("Installing AAR")
            self._snap.install()

        self.unit.status = ops.MaintenanceStatus("Configuring AAR")
        port = ops.Port(protocol="tcp", port=int(self.config["port"]))
        self._snap.configure(port, self.config["storage_config"], self.private_ip, self.public_ip)
        self.unit.set_ports(port)

        self.unit.set_workload_version(self._snap.version)
        self._snap.restart()
        self.unit.status = ops.ActiveStatus()

    def _on_stop(self, _: ops.StopEvent):
        self._snap.remove()

    def _on_aar_client_registered(self, _: ClientRegisteredEvent):
        self.unit.status = ops.ActiveStatus()


if __name__ == "__main__":
    ops.main(AARCharm)
