# Dobr encryption core

[Dobr](https://dobr.app) is a photo and file vault for Android. You draw a pattern to open a vault, and with Unlimited every pattern can open its own vault. Files are encrypted on the phone and the app has no internet permission.

This repo is the part of Dobr that decides whether your files are safe: how a pattern becomes a key, how files are encrypted and stored, and how the vault locks. It's published so you don't have to take our word for it. The rest of the app (screens, importing, Google Play billing) isn't here.

Start with [DESIGN.md](DESIGN.md). It explains the whole scheme in plain terms, including what Dobr can't protect against.

## What's here

| Path | What it is |
|---|---|
| `src/main/kotlin/app/dobr/crypto/VaultKeys.kt` | Pattern to vault id and key, and the per-file keys |
| `src/main/kotlin/app/dobr/crypto/ChunkedCipher.kt` | The encrypted file format (AES-256-GCM in 64 KB chunks) |
| `src/main/kotlin/app/dobr/vault/VaultStore.kt` | How a vault is laid out on disk and kept safe through crashes |
| `android/KeystoreDeviceSecret.kt` | The hardware-backed key that ties every vault to one phone |
| `android/VaultSession.kt` | When the vault locks and what locking wipes |
| `android/EncryptedDataSource.kt` | How videos play from the encrypted file without a decrypted copy |
| `android/AndroidManifest.xml`, `android/data_extraction_rules.xml` | No internet permission, no backups |
| `reference/` | A separate Python implementation written from DESIGN.md, plus shared test values |

The files under `src/` are exactly what the app uses. The files under `android/` need the Android SDK, so they're here to read rather than to build.

## Running the tests

The Kotlin tests run on a normal JVM, no Android needed. You need JDK 17 or later.

```
./gradlew test
```

They include tests that pin the exact pattern to key output, so an update can't quietly change it and lock everyone out of their vaults, plus tamper, truncation and crash recovery tests.

The Python implementation checks the same fixed values from the other side. It opens files written by the Kotlin code, and the Kotlin tests open a file written by the Python code.

```
pip install cryptography
python3 -m unittest discover reference
```

## Found a problem?

Please email hello@dobr.app rather than opening a public issue. See [SECURITY.md](SECURITY.md).

## Licence

Apache 2.0. See [LICENSE](LICENSE). The Dobr name and logo aren't covered by the licence.
