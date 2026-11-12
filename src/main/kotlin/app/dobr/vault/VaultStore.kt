package app.dobr.vault

import app.dobr.crypto.ChunkedCipher
import app.dobr.crypto.PatternKeys
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.SecureRandom

enum class ItemType { PHOTO, VIDEO, FILE }

data class VaultItem(
    val id: String,
    val name: String,
    val mime: String,
    val type: ItemType,
    val size: Long,
    val addedAt: Long,
    val durationMs: Long = 0,
    val hasThumb: Boolean = false,
) {
    fun toJson(): JSONObject = JSONObject()
        .put("id", id).put("name", name).put("mime", mime).put("type", type.name)
        .put("size", size).put("addedAt", addedAt).put("durationMs", durationMs).put("hasThumb", hasThumb)

    companion object {
        fun fromJson(o: JSONObject) = VaultItem(
            id = o.getString("id"),
            name = o.optString("name", "file"),
            mime = o.optString("mime", "application/octet-stream"),
            type = runCatching { ItemType.valueOf(o.getString("type")) }.getOrDefault(ItemType.FILE),
            size = o.optLong("size"),
            addedAt = o.optLong("addedAt"),
            durationMs = o.optLong("durationMs"),
            hasThumb = o.optBoolean("hasThumb"),
        )

        fun typeFor(mime: String): ItemType = when {
            mime.startsWith("image/") -> ItemType.PHOTO
            mime.startsWith("video/") -> ItemType.VIDEO
            else -> ItemType.FILE
        }
    }
}

/**
 * On disk:
 *   vaults/<vaultId>/v2                marks a vault that keeps one record per item
 *   vaults/<vaultId>/index.bin         encrypted list of items, a cache for fast opening
 *   vaults/<vaultId>/meta/<id>.bin     encrypted record for one item, the source of truth
 *   vaults/<vaultId>/items/<id>.bin    encrypted file contents
 *   vaults/<vaultId>/thumbs/<id>.bin   encrypted preview JPEG
 *
 * Folder names come from the pattern hash, so they say nothing about content.
 *
 * An item exists once its record is written, and the record is always written
 * last, after the contents have been synced to storage and read back. If the
 * app dies part way through, the next launch removes the unfinished contents
 * and the next unlock rebuilds the list from the records, so a crash can lose
 * the one item being added but never the ones already in the vault.
 */
class VaultStore(private val root: File) {
    private val random = SecureRandom()

    private fun vaultDir(vaultId: String) = File(root, "vaults/$vaultId")
    private fun indexFile(vaultId: String) = File(vaultDir(vaultId), "index.bin")
    private fun marker(vaultId: String) = File(vaultDir(vaultId), MARKER)
    private fun metaDir(vaultId: String) = File(vaultDir(vaultId), "meta")
    private fun metaFile(vaultId: String, itemId: String) = File(metaDir(vaultId), "$itemId.bin")
    fun itemFile(vaultId: String, itemId: String) = File(vaultDir(vaultId), "items/$itemId.bin")
    fun thumbFile(vaultId: String, itemId: String) = File(vaultDir(vaultId), "thumbs/$itemId.bin")

    fun exists(vaultId: String) = isVault(vaultDir(vaultId))

    private fun isVault(dir: File) = File(dir, "index.bin").exists() || File(dir, MARKER).exists()

    fun create(vaultId: String, encKey: ByteArray) {
        metaDir(vaultId).mkdirs()
        writeAtomic(marker(vaultId), ByteArray(0))
        saveIndex(vaultId, encKey, emptyList())
    }

    /**
     * Reads the item list and checks it against the per-item records: records
     * missing from the list are added back, and list entries whose record was
     * deleted are dropped. A repaired list is written back.
     */
    fun loadIndex(vaultId: String, encKey: ByteArray): List<VaultItem> {
        if (!marker(vaultId).exists()) return migrate(vaultId, encKey)
        val names = metaDir(vaultId).list() ?: throw java.io.IOException("Can't read vault records")
        val recorded = names.filter { it.endsWith(".bin") }.mapTo(HashSet()) { it.removeSuffix(".bin") }
        val listed = runCatching { readIndex(vaultId, encKey) }.getOrNull()
        val kept = listed.orEmpty().filter { it.id in recorded }.distinctBy { it.id }
        val keptIds = kept.mapTo(HashSet()) { it.id }
        val recovered = (recorded - keptIds).mapNotNull { id -> runCatching { readMeta(vaultId, encKey, id) }.getOrNull() }
        val items = kept + recovered
        if (listed == null || recovered.isNotEmpty() || kept.size != listed.size) {
            runCatching { saveIndex(vaultId, encKey, items) }
        }
        return items
    }

    /** Vaults made by the first test builds had only the list. Give every item its own record. */
    private fun migrate(vaultId: String, encKey: ByteArray): List<VaultItem> {
        val items = readIndex(vaultId, encKey) ?: emptyList()
        metaDir(vaultId).mkdirs()
        items.forEach { if (!metaFile(vaultId, it.id).exists()) writeMeta(vaultId, encKey, it) }
        writeAtomic(marker(vaultId), ByteArray(0))
        return items
    }

    private fun readIndex(vaultId: String, encKey: ByteArray): List<VaultItem>? {
        val file = indexFile(vaultId)
        if (!file.exists()) return null
        val key = PatternKeys.fileKey(encKey, "index", "index")
        try {
            val arr = JSONArray(String(ChunkedCipher.decryptFile(key, file)))
            return (0 until arr.length()).map { VaultItem.fromJson(arr.getJSONObject(it)) }
        } finally {
            key.fill(0)
        }
    }

    @Synchronized
    fun saveIndex(vaultId: String, encKey: ByteArray, items: List<VaultItem>) {
        vaultDir(vaultId).mkdirs()
        val arr = JSONArray().apply { items.forEach { put(it.toJson()) } }
        val key = PatternKeys.fileKey(encKey, "index", "index")
        try {
            writeAtomic(indexFile(vaultId), ChunkedCipher.encryptBytes(key, arr.toString().toByteArray()))
        } finally {
            key.fill(0)
        }
    }

    /** Writing an item's record is what makes it part of the vault. */
    fun writeMeta(vaultId: String, encKey: ByteArray, item: VaultItem) {
        val key = PatternKeys.fileKey(encKey, item.id, "meta")
        try {
            metaDir(vaultId).mkdirs()
            writeAtomic(metaFile(vaultId, item.id), ChunkedCipher.encryptBytes(key, item.toJson().toString().toByteArray()))
        } finally {
            key.fill(0)
        }
    }

    private fun readMeta(vaultId: String, encKey: ByteArray, itemId: String): VaultItem {
        val key = PatternKeys.fileKey(encKey, itemId, "meta")
        try {
            val item = VaultItem.fromJson(JSONObject(String(ChunkedCipher.decryptFile(key, metaFile(vaultId, itemId)))))
            check(item.id == itemId) { "Record does not match its file" }
            return item
        } finally {
            key.fill(0)
        }
    }

    fun newItemId(): String = ByteArray(12).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }

    /** Encrypts [input] into the vault and syncs it to storage. Returns the number of bytes stored. */
    fun writeItem(vaultId: String, encKey: ByteArray, itemId: String, input: InputStream): Long {
        val target = itemFile(vaultId, itemId).apply { parentFile?.mkdirs() }
        val tmp = File(target.parentFile, "$itemId.tmp")
        val key = dataKey(encKey, itemId)
        try {
            val size = FileOutputStream(tmp).use { fos ->
                val out = fos.buffered(256 * 1024)
                val n = ChunkedCipher.encrypt(key, input, out)
                out.flush()
                fos.fd.sync()
                n
            }
            move(tmp, target)
            return size
        } catch (e: Throwable) {
            tmp.delete()
            throw e
        } finally {
            key.fill(0)
        }
    }

    /** Reads a stored item back and checks every chunk decrypts and the length is right. */
    fun verifyItem(vaultId: String, encKey: ByteArray, itemId: String, expectedSize: Long): Boolean {
        val key = dataKey(encKey, itemId)
        return try {
            itemFile(vaultId, itemId).inputStream().buffered(256 * 1024).use { ChunkedCipher.decrypt(key, it, Discard) } == expectedSize
        } catch (e: Exception) {
            false
        } finally {
            key.fill(0)
        }
    }

    fun writeThumb(vaultId: String, encKey: ByteArray, itemId: String, jpeg: ByteArray) {
        val target = thumbFile(vaultId, itemId).apply { parentFile?.mkdirs() }
        val key = PatternKeys.fileKey(encKey, itemId, "thumb")
        try {
            writeAtomic(target, ChunkedCipher.encryptBytes(key, jpeg))
        } finally {
            key.fill(0)
        }
    }

    fun readThumb(vaultId: String, encKey: ByteArray, itemId: String): ByteArray? {
        val f = thumbFile(vaultId, itemId)
        if (!f.exists()) return null
        val key = PatternKeys.fileKey(encKey, itemId, "thumb")
        try {
            return ChunkedCipher.decryptFile(key, f)
        } finally {
            key.fill(0)
        }
    }

    fun dataKey(encKey: ByteArray, itemId: String) = PatternKeys.fileKey(encKey, itemId, "data")

    /** The record goes first, so a crash part way through can't bring a deleted item back. */
    fun deleteItem(vaultId: String, itemId: String) {
        val record = metaFile(vaultId, itemId)
        if (record.exists() && !record.delete()) throw java.io.IOException("Couldn't delete the item")
        itemFile(vaultId, itemId).delete()
        thumbFile(vaultId, itemId).delete()
    }

    /** How many vaults exist on this phone. Only used to enforce the free plan's one vault. */
    fun vaultCount(): Int = File(root, "vaults").listFiles()?.count { it.isDirectory && isVault(it) } ?: 0

    /**
     * Runs once at launch, before anything can be importing. Removes half
     * written files, and contents whose record was never written because the
     * app died mid import. The originals of those are still in the gallery,
     * since Dobr only offers to remove originals of finished items.
     */
    fun cleanTemp() {
        File(root, "vaults").listFiles()?.forEach { dir ->
            if (!dir.isDirectory) return@forEach
            val tmp = { f: File -> f.name.endsWith(".tmp") }
            dir.listFiles(tmp)?.forEach { it.delete() }
            for (sub in SUBDIRS) File(dir, sub).listFiles(tmp)?.forEach { it.delete() }
            if (!File(dir, MARKER).exists()) return@forEach
            val names = File(dir, "meta").list() ?: return@forEach
            val recorded = names.filter { it.endsWith(".bin") }.mapTo(HashSet()) { it.removeSuffix(".bin") }
            for (sub in listOf("items", "thumbs")) {
                File(dir, sub).listFiles { f -> f.name.endsWith(".bin") && f.name.removeSuffix(".bin") !in recorded }
                    ?.forEach { it.delete() }
            }
        }
    }

    /** Write to a temporary file, sync it, then swap it in, so a reader never sees half a file. */
    private fun writeAtomic(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val tmp = File(target.parentFile, target.name + ".tmp")
        try {
            FileOutputStream(tmp).use { out ->
                out.write(bytes)
                out.fd.sync()
            }
            move(tmp, target)
        } catch (e: Throwable) {
            tmp.delete()
            throw e
        }
    }

    private fun move(from: File, to: File) {
        Files.move(from.toPath(), to.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        // Best effort: make the rename itself durable.
        runCatching { FileChannel.open(to.parentFile!!.toPath(), StandardOpenOption.READ).use { it.force(true) } }
    }

    private object Discard : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {}
    }

    companion object {
        private const val MARKER = "v2"
        private val SUBDIRS = listOf("items", "thumbs", "meta")
    }
}
