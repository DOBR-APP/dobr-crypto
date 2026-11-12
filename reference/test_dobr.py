"""Run with: python3 -m unittest discover reference"""

import json
import os
import unittest

import dobr

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "vectors.json")) as f:
    V = json.load(f)


class Derivation(unittest.TestCase):
    def test_matches_the_app(self):
        d = V["derivation"]
        device_key = bytes.fromhex(d["device_key_hex"])
        vault_id, enc_key = dobr.derive(
            d["pattern"],
            bytes.fromhex(d["salt_hex"]),
            lambda data: dobr.hmac_sha256(device_key, data),
            d["iterations"],
        )
        self.assertEqual(vault_id, d["vault_id"])
        self.assertEqual(enc_key.hex(), d["enc_key_hex"])
        fk = d["file_key"]
        self.assertEqual(dobr.file_key(enc_key, fk["item_id"], fk["purpose"]).hex(), fk["key_hex"])

    def test_other_device_gives_other_vault(self):
        d = V["derivation"]
        a = dobr.derive(d["pattern"], bytes(32), lambda x: dobr.hmac_sha256(b"\x01" * 32, x), 1000)
        b = dobr.derive(d["pattern"], bytes(32), lambda x: dobr.hmac_sha256(b"\x02" * 32, x), 1000)
        self.assertNotEqual(a, b)

    def test_rejects_bad_patterns(self):
        for p in ([0, 1, 2], [0, 1, 2, 3, 4, 0], [0, 1, 2, 3, 4, 16]):
            with self.assertRaises(ValueError):
                dobr.encode_pattern(p)


class FileFormat(unittest.TestCase):
    def test_opens_files_written_by_the_app(self):
        v = V["files_written_by_kotlin"]
        key = bytes.fromhex(v["key_hex"])
        for f in v["files"]:
            expected = bytes((i * 7 + 3) % 256 for i in range(f["plain_length"]))
            self.assertEqual(dobr.decrypt(key, bytes.fromhex(f["hex"])), expected, f["name"])

    def test_own_reference_file(self):
        v = V["file_written_by_python"]
        expected = bytes(i % 251 for i in range(v["plain_length"]))
        self.assertEqual(dobr.decrypt(bytes.fromhex(v["key_hex"]), bytes.fromhex(v["hex"])), expected)

    def test_round_trip(self):
        key = os.urandom(32)
        for size in (0, 1, 1023, 1024, 1025, 4096, 70_000):
            data = os.urandom(size)
            self.assertEqual(dobr.decrypt(key, dobr.encrypt(key, data, 1024)), data)

    def test_tampering_is_caught(self):
        key = os.urandom(32)
        blob = bytearray(dobr.encrypt(key, os.urandom(5000), 1024))
        blob[len(blob) // 2] ^= 1
        with self.assertRaises(dobr.FormatError):
            dobr.decrypt(key, bytes(blob))

    def test_dropping_the_last_chunk_is_caught(self):
        key = os.urandom(32)
        blob = dobr.encrypt(key, os.urandom(4096), 1024)
        with self.assertRaises(dobr.FormatError):
            dobr.decrypt(key, blob[: -(1024 + dobr.TAG_LEN)])

    def test_swapping_chunks_is_caught(self):
        key = os.urandom(32)
        blob = dobr.encrypt(key, os.urandom(3000), 1024)
        h, full = dobr.HEADER_LEN, 1024 + dobr.TAG_LEN
        swapped = blob[:h] + blob[h + full:h + 2 * full] + blob[h:h + full] + blob[h + 2 * full:]
        with self.assertRaises(dobr.FormatError):
            dobr.decrypt(key, swapped)

    def test_file_from_another_item_is_caught(self):
        enc_key = os.urandom(32)
        blob = dobr.encrypt(dobr.file_key(enc_key, "item-a", "data"), b"photo")
        with self.assertRaises(dobr.FormatError):
            dobr.decrypt(dobr.file_key(enc_key, "item-b", "data"), blob)


if __name__ == "__main__":
    unittest.main()
