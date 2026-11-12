package app.dobr.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class PatternKeysTest {
    private val salt = ByteArray(32) { 7 }
    private val deviceA = DeviceSecret { PatternKeys.hmac(ByteArray(32) { 1 }, it) }
    private val deviceB = DeviceSecret { PatternKeys.hmac(ByteArray(32) { 2 }, it) }
    private val pattern = listOf(0, 1, 2, 3, 7, 11)

    @Test fun deterministic() {
        val a = PatternKeys.derive(pattern, salt, deviceA, 1000)
        val b = PatternKeys.derive(pattern, salt, deviceA, 1000)
        assertEquals(a.vaultId, b.vaultId)
        assertArrayEquals(a.encKey, b.encKey)
        assertEquals(32, a.vaultId.length)
    }

    @Test fun differentPatternDifferentVault() {
        val a = PatternKeys.derive(pattern, salt, deviceA, 1000)
        val b = PatternKeys.derive(pattern.reversed(), salt, deviceA, 1000)
        assertNotEquals(a.vaultId, b.vaultId)
    }

    @Test fun boundToDevice() {
        val a = PatternKeys.derive(pattern, salt, deviceA, 1000)
        val b = PatternKeys.derive(pattern, salt, deviceB, 1000)
        assertNotEquals(a.vaultId, b.vaultId)
    }

    @Test fun idAndKeyAreIndependent() {
        val a = PatternKeys.derive(pattern, salt, deviceA, 1000)
        assertNotEquals(a.vaultId, a.encKey.copyOf(16).joinToString("") { "%02x".format(it) })
    }

    /**
     * Pins the exact derivation. If this fails, a change has altered how
     * patterns turn into keys, and every existing vault would stop opening
     * after the update. Don't update these values; fix the change.
     */
    @Test fun derivationIsPinned() {
        val keys = PatternKeys.derive(pattern, salt, deviceA, 1000)
        assertEquals("c328bada1e8f958f971d199a3fcebd14", keys.vaultId)
        assertEquals("93334ad5029a9a93ef402440c3c833526c6243e44594885c7626a58f0d0d0ded", keys.encKey.hex())
        assertEquals(
            "67c1759b0e555d93563422f2d65e8ed97d6079899b57abc98023bfc3976b5f06",
            PatternKeys.fileKey(keys.encKey, "abc123", "data").hex(),
        )
        assertEquals(150_000, PatternKeys.ITERATIONS)
        assertEquals(6, PatternKeys.MIN_DOTS)
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it) }

    @Test fun betweenFindsDotsOnStraightLines() {
        // Grid:  0  1  2  3 /  4  5  6  7 /  8  9 10 11 / 12 13 14 15
        assertEquals(listOf(1, 2), PatternKeys.between(0, 3))
        assertEquals(listOf(5, 10), PatternKeys.between(0, 15))
        assertEquals(listOf(10, 5), PatternKeys.between(15, 0))
        assertEquals(listOf(4, 8), PatternKeys.between(0, 12))
        assertEquals(listOf(5), PatternKeys.between(0, 10))
        assertEquals(emptyList<Int>(), PatternKeys.between(0, 1))
        assertEquals(emptyList<Int>(), PatternKeys.between(0, 6))
        assertEquals(listOf(9), PatternKeys.between(6, 12))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsShortPattern() {
        PatternKeys.encode(listOf(0, 1, 2))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsRepeatedDots() {
        PatternKeys.encode(listOf(0, 1, 2, 3, 4, 0))
    }
}
