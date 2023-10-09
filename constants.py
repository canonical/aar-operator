#
# Anbox - The Android in a Box runtime environment
# Copyright 2023 Canonical Ltd.  All rights reserved.
#

from snap import AARSnap

SNAP_BASE_PATH = AARSnap.get_path()
AAR_CONFIG_PATH = SNAP_BASE_PATH  / "conf/main.yaml"

AAR_CERT_BASE_PATH =  SNAP_BASE_PATH / "certs"

AAR_SERVER_CERT_PATH = AAR_CERT_BASE_PATH / "server.crt"
AAR_SERVER_KEY_PATH = AAR_CERT_BASE_PATH / "server.key"

CLIENTS_CERT_PATH = AAR_CERT_BASE_PATH / "clients"
PUBLISHERS_CERT_PATH = AAR_CERT_BASE_PATH / "publishers"

