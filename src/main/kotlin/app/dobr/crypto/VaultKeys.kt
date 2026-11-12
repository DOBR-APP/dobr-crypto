package app.dobr.crypto

import javax.crypto.Mac
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** A secret that never leaves this phone. On Android it lives in the hardware keystore. */
fun interface DeviceSecret {
    fun mac(data: ByteArray): ByteArray
}

class VaultKeys(val vaultId: String, val encKey: ByteArray) {
    fun wipe() = encKey.fill(0)
}

/**
 * Turns a drawn pattern into a vault id and an encryption key.
 *
 *  1. PBKDF2-SHA256 over the pattern with a per-install salt (slows guessing).
 *  2. HMAC with a non-exportable keystore key (ties guessing to this device).
 *  3. Separate HMAC labels for the folder id and the encryption key.
 *
 * Every pattern produces a valid key, so every pattern can hold its own vault.
 * Nothing on disk says which patterns are in use.
 */
object PatternKeys {
    const val ITERATIONS = 150_000
    const val GRID = 4
    const val MIN_DOTS = 6

    /**
     * Dots that sit exactly on the straight line between two dots, in order.
     * Going from a corner to the opposite corner always picks up the middle
     * dots, so the same shape gives the same pattern however it's drawn.
     */
    fun between(from: Int, to: Int): List<Int> {
        val r1 = from / GRID; val c1 = from % GRID
        val dr = to / GRID - r1; val dc = to % GRID - c1
        val steps = gcd(kotlin.math.abs(dr), kotlin.math.abs(dc))
        if (steps <= 1) return emptyList()
        return (1 until steps).map { k -> (r1 + k * dr / steps) * GRID + (c1 + k * dc / steps) }
    }

    private tailrec fun gcd(a: Int, b: Int): Int = if (b == 0) a else gcd(b, a % b)

    fun encode(pattern: List<Int>): String {
        require(pattern.size >= MIN_DOTS) { "Pattern too short" }
        require(pattern.toSet().size == pattern.size) { "Dots repeat" }
        require(pattern.all { it in 0 until GRID * GRID }) { "Dot out of range" }
        return "dobr-pattern-v1:" + pattern.joinToString(",")
    }

    fun derive(
        pattern: List<Int>,
        salt: ByteArray,
        device: DeviceSecret,
        iterations: Int = ITERATIONS,
    ): VaultKeys {
        val chars = encode(pattern).toCharArray()
        val spec = PBEKeySpec(chars, salt, iterations, 256)
        val stretched = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        spec.clearPassword()
        chars.fill('\u0000')
        val bound = device.mac(stretched)
        stretched.fill(0)
        val id = hmac(bound, "dobr/vault-id/v1".toByteArray()).copyOf(16).toHex()
        val enc = hmac(bound, "dobr/enc-key/v1".toByteArray())
        bound.fill(0)
        return VaultKeys(id, enc)
    }

    /** Each file gets its own key, so nonce reuse across files is impossible. */
    fun fileKey(encKey: ByteArray, itemId: String, purpose: String): ByteArray =
        hmac(encKey, "dobr/file/v1/$itemId/$purpose".toByteArray())

    fun hmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
