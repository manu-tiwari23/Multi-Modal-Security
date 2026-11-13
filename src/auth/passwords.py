"""Versioned scrypt password hashes; random salts, constant-time verification."""

import hashlib
import hmac
import secrets


def hash_password(password):
    if not 15 <= len(password) <= 128:
        raise ValueError("Use a password or passphrase between 15 and 128 characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=3, maxmem=64 * 1024 * 1024)
    return f"scrypt-v1${salt.hex()}${digest.hex()}"


def verify_password(password, encoded):
    try:
        version, salt, expected = encoded.split("$")
        if version != "scrypt-v1" or not 1 <= len(password) <= 128 or len(salt) != 32 or len(expected) != 128:
            return False
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=32768, r=8, p=3, maxmem=64 * 1024 * 1024)
        return hmac.compare_digest(digest.hex(), expected)
    except (ValueError, TypeError):
        return False
