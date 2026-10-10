#!/usr/bin/env python3
"""Unseal the 533c's Windows key offline, from Linux, without booting Windows.

Dell's Windows driver seals the sensor key with DPAPI under SYSTEM (S-1-5-18),
with no entropy, and stores the sealed copy on the sensor (slot bb010002).
SYSTEM's DPAPI master keys are protected by the DPAPI_SYSTEM LSA secret, which
the SYSTEM and SECURITY hives hold, so a mounted Windows partition is enough:
no Windows password and no running Windows. A BitLocker volume must be
unlocked first (dislocker, cryptsetup bitlk).

  sudo scripts/extract-windows-psk.sh --533c goodix533c.dpapi
  scripts/unseal-windows-psk-offline.py goodix533c.dpapi /mnt/windows > goodix533c.psk
  sudo scripts/install-windows-psk.sh --533c goodix533c.psk

Needs impacket (pip install impacket). Prints the key as hexadecimal; DPAPI's
HMAC and the 32-byte length check that the right blob and hives were used.
"""
import os
import sys

from impacket.dpapi import DPAPI_BLOB, MasterKey, MasterKeyFile
from impacket.examples.secretsdump import LocalOperations, LSASecrets


def dpapi_system_user_key(system, security):
    """Returns the user half of the DPAPI_SYSTEM LSA secret."""
    found = {}

    def keep(_secret_type, secret):
        for line in secret.splitlines():
            if line.startswith("dpapi_userkey:"):
                found["user"] = bytes.fromhex(line.split(":", 1)[1].removeprefix("0x"))

    lsa = LSASecrets(security, LocalOperations(system).getBootKey(), isRemote=False,
                     perSecretCallback=keep)
    lsa.dumpSecrets()
    lsa.finish()
    if "user" not in found:
        sys.exit("no DPAPI_SYSTEM secret in the SECURITY hive")
    return found["user"]


def master_key(protect_dir, guid, user_key):
    """Returns the decrypted SYSTEM master key @guid."""
    path = os.path.join(protect_dir, guid)
    if not os.path.exists(path):
        sys.exit(f"master key {guid} is not in {protect_dir}; "
                 "is this the Windows installation that last used the sensor?")
    data = open(path, "rb").read()
    mkf = MasterKeyFile(data)
    key = MasterKey(data[len(mkf):][: mkf["MasterKeyLen"]]).decrypt(user_key)
    if key is None:
        sys.exit(f"master key {guid} did not decrypt")
    return key


def main(blob_file, windows_root):
    windows = os.path.join(windows_root, "Windows", "System32")
    config = os.path.join(windows, "config")
    protect_dir = os.path.join(windows, "Microsoft", "Protect", "S-1-5-18", "User")
    blob = DPAPI_BLOB(open(blob_file, "rb").read())
    guid = blob["GuidMasterKey"]
    guid = "%08x-%04x-%04x-%s-%s" % (
        int.from_bytes(guid[0:4], "little"), int.from_bytes(guid[4:6], "little"),
        int.from_bytes(guid[6:8], "little"), guid[8:10].hex(), guid[10:16].hex())
    user_key = dpapi_system_user_key(os.path.join(config, "SYSTEM"),
                                     os.path.join(config, "SECURITY"))
    key = blob.decrypt(master_key(protect_dir, guid, user_key))
    if key is None or len(key) != 32:
        sys.exit("the blob did not unseal to a 32-byte key")
    print(key.hex())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(*sys.argv[1:])
