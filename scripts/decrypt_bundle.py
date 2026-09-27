"""
Decrypt a LOGVAULT encrypted forensic bundle (.lvault) and check its SHA-256 manifest.

Usage:  python scripts/decrypt_bundle.py logvault-forensics-....lvault [output.zip]
Needs only Python 3 and the 'cryptography' package (pip install cryptography).
"""
import getpass
import hashlib
import io
import json
import sys
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"LVAULT1\n"


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else src.rsplit(".", 1)[0] + ".zip"
    blob = open(src, "rb").read()
    if not blob.startswith(MAGIC):
        sys.exit("Not a LOGVAULT encrypted bundle")
    passphrase = getpass.getpass("Passphrase: ")
    salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
    key = hashlib.scrypt(passphrase.encode(), salt=salt, n=2 ** 15, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    try:
        data = AESGCM(key).decrypt(nonce, ct, MAGIC)
    except InvalidTag:
        sys.exit("Wrong passphrase, or the file was modified")
    open(out, "wb").write(data)

    z = zipfile.ZipFile(io.BytesIO(data))
    manifest = json.loads(z.read("manifest.json"))
    bad = [n for n, m in manifest["files"].items() if hashlib.sha256(z.read(n)).hexdigest() != m["sha256"]]
    print(f"Decrypted to {out}: {manifest['event_count']} events, {manifest['alert_count']} alerts")
    print("SHA-256 manifest: " + ("all files match" if not bad else f"MISMATCH in {', '.join(bad)}"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
