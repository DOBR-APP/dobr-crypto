package app.dobr.vault

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

/** Crash and recovery behaviour of the vault store. */
class VaultStoreTest {
    private lateinit var root: File
    private lateinit var store: VaultStore
    private val vault = "a".repeat(32)
    private val key = ByteArray(32) { (it * 3).toByte() }

    @Before fun setUp() {
        root = Files.createTempDirectory("dobr").toFile()
        store = VaultStore(root)
        store.create(vault, key)
    }

    private fun add(name: String, bytes: ByteArray = name.toByteArray()): VaultItem {
        val id = store.newItemId()
        val size = store.writeItem(vault, key, id, bytes.inputStream())
        assertTrue(store.verifyItem(vault, key, id, size))
        val item = VaultItem(id, name, "image/jpeg", ItemType.PHOTO, size, System.currentTimeMillis())
        store.writeMeta(vault, key, item)
        return item
    }

    @Test fun newVaultExistsAndIsEmpty() {
        assertTrue(store.exists(vault))
        assertEquals(1, store.vaultCount())
        assertEquals(emptyList<VaultItem>(), store.loadIndex(vault, key))
    }

    @Test fun itemsSurviveACrashBeforeTheListIsSaved() {
        val a = add("a.jpg")
        val b = add("b.jpg")
        // The app died before the batch's list was saved.
        val loaded = store.loadIndex(vault, key)
        assertEquals(setOf(a.id, b.id), loaded.map { it.id }.toSet())
    }

    @Test fun unreadableListIsRebuiltFromRecords() {
        val a = add("a.jpg")
        store.saveIndex(vault, key, listOf(a))
        File(root, "vaults/$vault/index.bin").writeBytes(ByteArray(40) { 1 })
        assertEquals(listOf(a.id), store.loadIndex(vault, key).map { it.id })
    }

    @Test fun deletedItemDoesNotComeBack() {
        val a = add("a.jpg")
        val b = add("b.jpg")
        store.saveIndex(vault, key, listOf(a, b))
        store.deleteItem(vault, a.id)
        // Crash before the list was saved again: the record is gone, so is the item.
        assertEquals(listOf(b.id), store.loadIndex(vault, key).map { it.id })
        assertFalse(store.itemFile(vault, a.id).exists())
    }

    @Test fun cleanupRemovesOnlyUnfinishedContents() {
        val a = add("a.jpg")
        store.saveIndex(vault, key, listOf(a))
        // Contents written but the app died before the record.
        val orphan = store.newItemId()
        store.writeItem(vault, key, orphan, "half".toByteArray().inputStream())
        File(root, "vaults/$vault/items/${store.newItemId()}.tmp").writeBytes(ByteArray(10))
        store.cleanTemp()
        assertTrue(store.itemFile(vault, a.id).exists())
        assertFalse(store.itemFile(vault, orphan).exists())
        assertTrue(File(root, "vaults/$vault/items").listFiles()!!.none { it.name.endsWith(".tmp") })
        assertEquals(listOf(a.id), store.loadIndex(vault, key).map { it.id })
    }

    @Test fun verifyCatchesDamage() {
        val id = store.newItemId()
        val size = store.writeItem(vault, key, id, ByteArray(200_000) { it.toByte() }.inputStream())
        assertTrue(store.verifyItem(vault, key, id, size))
        assertFalse(store.verifyItem(vault, key, id, size + 1))
        val f = store.itemFile(vault, id)
        val bytes = f.readBytes()
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 1).toByte()
        f.writeBytes(bytes)
        assertFalse(store.verifyItem(vault, key, id, size))
    }

    @Test fun earlyTestVaultsAreMigratedNotWiped() {
        // A vault from the first test builds: a list, contents, no per-item records.
        val legacy = "b".repeat(32)
        val id = store.newItemId()
        val size = store.writeItem(legacy, key, id, "photo".toByteArray().inputStream())
        val item = VaultItem(id, "p.jpg", "image/jpeg", ItemType.PHOTO, size, 1L)
        store.saveIndex(legacy, key, listOf(item))
        assertTrue(store.exists(legacy))

        store.cleanTemp()
        assertTrue("cleanup must not touch an unmigrated vault", store.itemFile(legacy, id).exists())

        assertEquals(listOf(id), store.loadIndex(legacy, key).map { it.id })
        store.cleanTemp()
        assertTrue(store.itemFile(legacy, id).exists())
        assertEquals(listOf(id), store.loadIndex(legacy, key).map { it.id })
    }

    @Test fun otherPatternsSeeNothing() {
        add("a.jpg")
        assertFalse(store.exists("c".repeat(32)))
    }
}
