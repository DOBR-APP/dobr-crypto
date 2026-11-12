"""
A second, independent implementation of Dobr's key derivation and file
format, written from DESIGN.md rather than from the Kotlin code.

If this and the Kotlin code ever disagree, one of them doesn't match the
spec. The tests in test_dobr.py check both directions: files written by
the app open here, and files written here open in the app's code.

Needs the `cryptography` package (pip install cryptography).
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GRID = 4
MIN_DOTS = 6
ITERATIONS = 150_000

MAGIC = b"DBR1"
HEADER_LEN = 16
TAG_LEN = 16
DEFAULT_CHUNK = 64 * 1024
MIN_CHUNK = 1024
MAX_CHUNK = 16 * 1024 * 1024


class FormatError(Exception):
    """The data isn't a valid Dobr file, or it was changed after it was written."""


# Pattern to key

def encode_pattern(pattern):
    """Dots are numbered 0 to 15, left to right, top to bottom."""
    if len(pattern) < MIN_DOTS:
        raise ValueError("pattern too short")
    if len(set(pattern)) != len(pattern):
        raise ValueError("dots repeat")
    if any(not 0 <= d < GRID * GRID for d in pattern):
        raise ValueError("dot out of range")
    return "dobr-pattern-v1:" + ",".join(str(d) for d in pattern)


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def derive(pattern, salt, device_mac, iterations=ITERATIONS):
    """
    Returns (vault_id, enc_key).

    device_mac stands in for the phone's keystore: a function that takes
    bytes and returns HMAC-SHA256 under a key that never leaves the phone.
    On a real phone there is no way to run this step anywhere else.
    """
    stretched = hashlib.pbkdf2_hmac(
        "sha256", encode_pattern(pattern).encode("utf-8"), salt, iterations, 32
    )
    bound = device_mac(stretched)
    vault_id = hmac_sha256(bound, b"dobr/vault-id/v1")[:16].hex()
    enc_key = hmac_sha256(bound, b"dobr/enc-key/v1")
    return vault_id, enc_key


def file_key(enc_key, item_id, purpose):
    """purpose is "data", "thumb" or "meta". The item list uses ("index", "index")."""
    return hmac_sha256(enc_key, f"dobr/file/v1/{item_id}/{purpose}".encode("utf-8"))


# File format

def _nonce(prefix, index):
    return prefix + struct.pack(">I", index)


def _aad(header, index, last):
    return header + struct.pack(">IB", index, 1 if last else 0)


def encrypt(key, data, chunk_size=DEFAULT_CHUNK, prefix=None):
    if len(key) != 32:
        raise ValueError("AES-256 key required")
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise ValueError("bad chunk size")
    prefix = os.urandom(8) if prefix is None else prefix
    header = MAGIC + struct.pack(">I", chunk_size) + prefix
    aes = AESGCM(key)
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)] or [b""]
    out = [header]
    for i, chunk in enumerate(chunks):
        last = i == len(chunks) - 1
        out.append(aes.encrypt(_nonce(prefix, i), chunk, _aad(header, i, last)))
    return b"".join(out)


def decrypt(key, blob):
    if len(blob) < HEADER_LEN:
        raise FormatError("truncated header")
    header = blob[:HEADER_LEN]
    if header[:4] != MAGIC:
        raise FormatError("not a Dobr file")
    (chunk_size,) = struct.unpack(">I", header[4:8])
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise FormatError("bad chunk size")
    prefix = header[8:16]
    body = blob[HEADER_LEN:]
    full = chunk_size + TAG_LEN
    pieces = [body[i:i + full] for i in range(0, len(body), full)]
    if not pieces or len(pieces[-1]) < TAG_LEN:
        raise FormatError("missing or truncated chunk")
    aes = AESGCM(key)
    out = []
    for i, piece in enumerate(pieces):
        last = i == len(pieces) - 1
        try:
            out.append(aes.decrypt(_nonce(prefix, i), piece, _aad(header, i, last)))
        except Exception as e:
            raise FormatError(f"chunk {i} failed authentication") from e
    return b"".join(out)
