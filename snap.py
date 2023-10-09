#
# Anbox - The Android in a Box runtime environment
# Copyright 2023 Canonical Ltd.  All rights reserved.
#

from pathlib import Path
import ops
from lib.charms.operator_libs_linux.v2 import snap

SNAP_NAME = "aar"
SNAP_COMMON_PATH = Path("/var/snap/aar/common")

class AARSnap:

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

    @classmethod
    def get_path(cls) -> Path:
        return SNAP_COMMON_PATH
