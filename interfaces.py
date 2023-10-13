#
# Copyright 2023 Canonical Ltd.  All rights reserved.
#

import os
import shutil
import logging
import ops
from helpers import pki
import subprocess

from charm import AARCharm
from constants import AAR_SERVER_CERT_PATH, CLIENTS_CERT_PATH, PUBLISHERS_CERT_PATH

logger = logging.getLogger(__name__)

class ClientRegisteredEvent(ops.EventBase):
    """Event emitted when a new client is registered"""

class AAREndpointProviderEvents(ops.CharmEvents):
    client_registered = ops.EventSource(ClientRegisteredEvent)

class AAREndpointProvider(ops.Object):
    on: ops.CharmEvents = AAREndpointProviderEvents()

    def  __init__(self, charm: AARCharm, relation_name: str):
        self._charm = charm
        events = self._charm.on[relation_name]
        self.framework.observe(events.relation_changed, self._on_aar_changed)
        self.framework.observe(events.relation_joined, self._on_aar_joined)

    def _on_aar_joined(self, event: ops.RelationJoinedEvent):
        with open(AAR_SERVER_CERT_PATH, "r") as f:
            cert = f.read()
        if not cert:
            self._charm.unit.status = ops.BlockedStatus("No registry certificate")
            return

        listen_address = self._charm.private_ip
        location = self._charm.config['location']
        if location:
            listen_address = location

        unit_data = event.relation.data[self._charm.unit]
        unit_data["certificate"] = cert
        unit_data["fingerprint"] = pki.get_fingerprint(cert)
        unit_data["ip"] = listen_address
        unit_data["port"] = str(self._charm.config['port'])

    def _on_aar_changed(self, event: ops.RelationChangedEvent):
        self._charm.unit.status = ops.MaintenanceStatus("Confguring new AAR Client")
        # remove certificates of previous clients to avoid conflicts for same
        # certificates
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
                self._charm.unit.status = ops.BlockedStatus(
                    "Invalid relation {} to {}".format("arr-" + mode, event.relation.name)
                )
                return
            ams_clients.append(event.relation.data[unit])

        if not ams_clients:
            return
        for client in ams_clients:
            try:
                self._register_aar_client(client["certificate"], event.relation.name)
            except subprocess.CalledProcessError as ex:
                logger.error(f"failed to add client to aar: {ex.output}")
                self._charm.unit.status = ops.BlockedStatus('Failed to register client certificate')
                return
        self.on.client_registered.emit()

    def _remove_all_certificates(self):
        """Remove all old certificates held by AAR.

        All client certificates are kept by juju in the relation until the hook
        fails, so every time a new client is registered, the previous certificates
        will be added again. To avoid duplicates and properly take into account
        units that departed, we remove all certificates and add the ones that
        are still active again.
        """
        shutil.rmtree(CLIENTS_CERT_PATH)
        shutil.rmtree(PUBLISHERS_CERT_PATH)
        os.makedirs(CLIENTS_CERT_PATH, 0o700, exist_ok=True)
        os.makedirs(PUBLISHERS_CERT_PATH, 0o700, exist_ok=True)

    def _register_aar_client(self, client_certificate: str, mode: str):
        client_certificate = client_certificate.replace("\\n", "\n").strip('"')
        cmd = ["/snap/bin/aar", "trust", "add"]
        if mode == "publisher":
            cmd.append("--publisher")
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, input=client_certificate.encode("utf-8"))
            logger.info("new client registered")
        except subprocess.CalledProcessError as ex:
            if 'certificate already exists' in ex.output:
                logger.warning("client already registered")
                return
            raise

