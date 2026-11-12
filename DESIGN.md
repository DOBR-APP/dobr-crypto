# How Dobr's encryption works

This is the full description of how Dobr turns a pattern into keys, how it stores files, and where its protection stops. The code in this repo is what the app runs. `reference/dobr.py` is a second implementation written from this document, and the tests check that the two agree.

## Pattern to key

**The pattern.** A 4 by 4 grid, dots numbered 0 to 15 from left to right and top to bottom. A pattern is at least 6 dots, with no dot used twice. If a line passes straight over a dot that hasn't been used yet, that dot is added automatically, the same as Android's own lock pattern (`PatternKeys.between`). So a shape always means the same sequence however fast it's drawn.

The sequence is written as a string:

```
dobr-pattern-v1:0,1,2,3,7,11
```

This string only ever exists in memory while a key is being made.

**Stretching.** PBKDF2 with HMAC-SHA256, 150,000 rounds, 32 byte output. The salt is 32 random bytes made the first time Dobr runs and kept in the app's private storage.

**Tying it to the phone.** The stretched value goes through HMAC-SHA256 with a key generated inside the Android Keystore (`android/KeystoreDeviceSecret.kt`). Dobr asks for StrongBox first and falls back to the regular hardware-backed keystore if the phone has none. The key can be used but can't be exported, so this step only runs on the phone that made it. Copying the app's files to another device, or to a computer, gets you nothing you can test guesses against.

**Two outputs.** From that result (call it `bound`):

```
vaultId = first 16 bytes of HMAC-SHA256(bound, "dobr/vault-id/v1"), as hex
encKey  = HMAC-SHA256(bound, "dobr/enc-key/v1")
```

The vault id is just a folder name. A wrong pattern gives a different id, which points at a folder that doesn't exist, so the app says the pattern doesn't open a vault. Nothing is stored that could tell a wrong pattern from a pattern that simply has no vault yet, which is how Dobr can offer as many vaults as there are patterns without keeping a list of them.

## Keys for each file

Every item gets a random 12 byte id. Its keys are:

```
contents  HMAC-SHA256(encKey, "dobr/file/v1/<id>/data")
preview   HMAC-SHA256(encKey, "dobr/file/v1/<id>/thumb")
record    HMAC-SHA256(encKey, "dobr/file/v1/<id>/meta")
```

The vault's item list uses `dobr/file/v1/index/index`.

Because each file has its own key, a file moved into another item's place, or another vault, fails to decrypt instead of showing the wrong thing.

## File format

Every encrypted file, whether it's a photo, a preview, a record or the item list, uses the same format (`ChunkedCipher.kt`).

```
header   "DBR1" | chunk size (4 bytes, big endian) | nonce prefix (8 random bytes)
chunk 0  AES-256-GCM ciphertext | 16 byte tag
chunk 1  ...
```

- The plaintext is split into chunks of the chunk size (64 KB in the app). The last chunk can be shorter. An empty file is one empty chunk, which is just a tag.
- Chunk `i` uses the nonce `prefix | i`, where `i` is 4 bytes big endian.
- Each chunk's associated data is `header | i | last`, where `last` is one byte, 1 for the final chunk and 0 otherwise.

So the header, each chunk's position, and which chunk is last are all covered by the tags. Changing a byte, swapping chunks, or cutting chunks off the end all make decryption fail. Fixed size chunks also mean any part of a file can be decrypted on its own, which is how videos play and seek without a decrypted copy being written anywhere (`android/EncryptedDataSource.kt`).

## Vault layout on disk

```
vaults/<vaultId>/v2                  marks the current layout
vaults/<vaultId>/index.bin           item list, a cache so the vault opens quickly
vaults/<vaultId>/meta/<id>.bin       one encrypted record per item: name, type, size, date
vaults/<vaultId>/items/<id>.bin      encrypted contents
vaults/<vaultId>/thumbs/<id>.bin     encrypted preview
```

File names, types and dates are only inside the encrypted records. On disk everything is a random id.

**Crash safety** (`VaultStore.kt`). Files are written to a temporary file, synced, then renamed into place. When adding an item, the contents go first. Dobr then reads them back and decrypts every chunk to check them. Only after that is the item's record written, and the record is what makes the item part of the vault. If the app dies part way through, the next launch deletes contents that have no record, and the next unlock rebuilds the item list from the records. Deleting removes the record first, so a crash can't bring a deleted item back. Dobr only offers to remove the original from the gallery once the stored copy has passed that check.

## While the vault is open

`android/VaultSession.kt` holds the only copy of the vault key. Locking zeroes it, drops the cached previews and deletes any temporary file made for "Open in another app".

Dobr locks when it leaves the screen or the screen turns off. The one exception is a picker, purchase sheet or "Open in another app" that Dobr itself started: those get up to two minutes, and the exception ends as soon as Dobr is back on screen. Turning the screen off always locks.

Photos are decrypted into memory to be shown. Videos are decrypted a chunk at a time as they play. Nothing readable is written to storage, apart from the two actions whose whole job is to make a readable copy: "Save a copy outside Dobr" and "Open in another app".

## What leaves the phone

Nothing. `android/AndroidManifest.xml` removes the internet permission and the network state permissions, even if a library tries to add them. Android's cloud backup and phone to phone transfer are switched off (`android/data_extraction_rules.xml`), so a vault never ends up in Google Drive or on a new phone. Purchases are handled by Google Play on the phone.

## Known limits

These are the things Dobr doesn't protect against, or only partly does.

**No lockout.** Dobr never locks you out after wrong patterns, because every pattern is a valid key and there's nothing to count failures against without storing something. Someone holding the phone can keep trying. Every try has to run the full 150,000 rounds plus a call into the secure hardware, but that only slows guessing down, it doesn't stop it. For scale, counting with the grid's rules there are about 1.3 million possible 6 dot patterns, about 79 million 8 dot patterns, and about 4.35 trillion patterns of 6 dots or more in total. People don't pick patterns at random, though, so a simple shape is far easier to find than those numbers suggest. Use 8 dots or more and avoid letters and plain shapes.

**Someone who can read the app's private storage.** On a rooted phone, or from a forensic copy of one, the files are readable as files. Without the pattern and the phone's keystore key they can't be decrypted, but some things can be seen without decrypting anything:

- how many vault folders exist
- how many items each one holds and roughly how big each item is
- when files were last changed

So a decoy vault works against someone looking at the screen. It is not hidden from a forensic examination of the phone's storage.

**Memory.** Keys are byte arrays that Dobr zeroes when it locks, but the Java runtime and the phone's crypto provider can make copies that Dobr has no way to wipe. Previews and the open photo are held in memory while the vault is open. Someone with full control of a running, unlocked phone can see what's on it.

**Copies Dobr doesn't control.** Photos already backed up before they were added, photos sent to someone, and anything saved out of Dobr are outside the vault.

**Losing the vault.** There's no recovery by design. Uninstalling, clearing the app's storage, resetting the phone, or the keystore key being wiped all make every vault unreadable for good.

**Reusing the list key.** The item list is rewritten with the same key each time it changes, with a fresh random 8 byte nonce prefix every time. A nonce collision would take something like four billion saves of one vault, so this isn't a practical problem, but it's noted here for completeness. Every other file is written once per key.

**This repo and the Play build.** The app is built from this code, but builds aren't reproducible yet, so there's no way for you to prove the copy on Google Play matches it byte for byte.

## Changing any of this

The pattern string, the round count, the HMAC labels and the file format are all fixed. If any of them changed, every existing vault would stop opening. `PatternKeysTest.derivationIsPinned` and `reference/vectors.json` exist to catch that. A future change would need a new version label and a migration that runs while the vault is open.
