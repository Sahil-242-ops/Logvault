"""
Passphrase encryption for evidence leaving LOGVAULT (forensic bundles).

File layout (.lvault):  MAGIC | salt (16 bytes) | nonce (12 bytes) | AES-256-GCM ciphertext+tag
Key = scrypt(passphrase, salt, n=2^15, r=8, p=1) -> 32 bytes. GCM authenticates the whole file,
so a wrong passphrase or any modified byte fails to decrypt instead of producing garbage.
scripts/decrypt_bundle.py decrypts it without LOGVAULT installed.
"""
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"LVAULT1\n"
MIN_PASSPHRASE = 10


def _key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=64 * 1024 * 1024, dklen=32)


def encrypt(data: bytes, passphrase: str) -> bytes:
    if len(passphrase or "") < MIN_PASSPHRASE:
        raise ValueError(f"Passphrase must be at least {MIN_PASSPHRASE} characters")
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(passphrase, salt)).encrypt(nonce, data, MAGIC)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise ValueError("Not a LOGVAULT encrypted bundle")
    salt, nonce, ct = blob[8:24], blob[24:36], blob[36:]
    return AESGCM(_key(passphrase, salt)).decrypt(nonce, ct, MAGIC)
