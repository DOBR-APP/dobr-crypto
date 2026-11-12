package app.dobr.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.GeneralSecurityException
import kotlin.random.Random

class ChunkedCipherTest {
    private val key = ByteArray(32) { it.toByte() }

    private fun roundTrip(size: Int, chunk: Int = 1024) {
        val plain = Random(size).nextBytes(size)
        val out = ByteArrayOutputStream()
        ChunkedCipher.encrypt(key, plain.inputStream(), out, chunk)
        val back = ByteArrayOutputStream()
        ChunkedCipher.decrypt(key, out.toByteArray().inputStream(), back)
        assertArrayEquals("size $size", plain, back.toByteArray())
    }

    @Test fun roundTripsEdgeSizes() {
        listOf(0, 1, 1023, 1024, 1025, 2048, 5000, 100_000).forEach { roundTrip(it) }
    }

    @Test fun roundTripsDefaultChunk() = roundTrip(300_000, ChunkedCipher.DEFAULT_CHUNK)

    @Test fun wrongKeyFails() {
        val enc = ChunkedCipher.encryptBytes(key, "hello".toByteArray())
        val other = key.copyOf().also { it[0] = 99 }
        expectFailure { ChunkedCipher.decryptBytes(other, enc) }
    }

    @Test fun tamperFails() {
        val enc = ChunkedCipher.encryptBytes(key, Random(1).nextBytes(5000))
        enc[enc.size / 2] = (enc[enc.size / 2].toInt() xor 1).toByte()
        expectFailure { ChunkedCipher.decryptBytes(key, enc) }
    }

    @Test fun truncationAtChunkBoundaryFails() {
        val plain = Random(2).nextBytes(4096)
        val out = ByteArrayOutputStream()
        ChunkedCipher.encrypt(key, plain.inputStream(), out, 1024)
        val enc = out.toByteArray()
        // Drop the final chunk entirely. The new last chunk was not marked last.
        val cut = enc.copyOf(enc.size - (1024 + ChunkedCipher.TAG_LEN))
        expectFailure { ChunkedCipher.decryptBytes(key, cut) }
    }

    @Test fun sameInputEncryptsDifferently() {
        val a = ChunkedCipher.encryptBytes(key, "same".toByteArray())
        val b = ChunkedCipher.encryptBytes(key, "same".toByteArray())
        assertNotEquals(a.toList(), b.toList())
    }

    @Test fun randomAccessMatchesPlain() {
        val plain = Random(3).nextBytes(10_000)
        val file = File.createTempFile("dobr", ".bin")
        try {
            file.outputStream().use { ChunkedCipher.encrypt(key, plain.inputStream(), it, 1024) }
            ChunkedFileReader(file, key).use { reader ->
                assertEquals(plain.size.toLong(), reader.plainLength)
                val rnd = Random(4)
                repeat(200) {
                    val pos = rnd.nextInt(plain.size)
                    val len = rnd.nextInt(1, 3000)
                    val buf = ByteArray(len)
                    var got = 0
                    while (got < len) {
                        val n = reader.read((pos + got).toLong(), buf, got, len - got)
                        if (n < 0) break
                        got += n
                    }
                    val expected = plain.copyOfRange(pos, minOf(plain.size, pos + len))
                    assertArrayEquals(expected, buf.copyOf(got))
                }
                assertEquals(-1, reader.read(plain.size.toLong(), ByteArray(4), 0, 4))
            }
        } finally {
            file.delete()
        }
    }

    @Test fun randomAccessExactMultipleOfChunk() {
        val plain = Random(5).nextBytes(2048)
        val file = File.createTempFile("dobr", ".bin")
        try {
            file.outputStream().use { ChunkedCipher.encrypt(key, plain.inputStream(), it, 1024) }
            ChunkedFileReader(file, key).use { reader ->
                assertEquals(2048L, reader.plainLength)
                val buf = ByteArray(1024)
                assertEquals(1024, reader.read(1024, buf, 0, 1024))
                assertArrayEquals(plain.copyOfRange(1024, 2048), buf)
            }
        } finally {
            file.delete()
        }
    }

    private fun expectFailure(block: () -> Unit) {
        try {
            block()
            fail("Expected failure")
        } catch (e: GeneralSecurityException) {
            // expected
        }
    }

    /**
     * A file written by an independent implementation of the format. If this
     * stops decrypting, the on-disk format has changed and existing vaults
     * would no longer open.
     */
    @Test fun readsReferenceFile() {
        val key = ByteArray(32) { it.toByte() }
        val expected = ByteArray(1500) { (it % 251).toByte() }
        val blob = REFERENCE.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        org.junit.Assert.assertArrayEquals(expected, ChunkedCipher.decryptBytes(key, blob))
        val file = java.io.File.createTempFile("ref", ".bin").apply { writeBytes(blob); deleteOnExit() }
        ChunkedFileReader(file, key).use { reader ->
            org.junit.Assert.assertEquals(1500L, reader.plainLength)
            org.junit.Assert.assertArrayEquals(expected, reader.stream().readBytes())
            val s = reader.stream()
            s.skip(1000)
            s.mark(0)
            // Crosses the chunk boundary at 1024, where a single read returns short.
            val a = ByteArray(100).also { java.io.DataInputStream(s).readFully(it) }
            s.reset()
            val b = ByteArray(100).also { java.io.DataInputStream(s).readFully(it) }
            org.junit.Assert.assertArrayEquals(a, b)
            org.junit.Assert.assertArrayEquals(expected.copyOfRange(1000, 1100), a)
        }
    }

    private companion object {
        const val REFERENCE =
            "4442523100000400090807060504030226c663fae243d19460acea41fa8e9b1f4d9635681545d6754881426222251c95" +
            "8b07af748908cc256ead2f0e8836ab093e64ec83e153a99500c399e28d8628d94d92c2b9856a8d1ad732499f5bbf85a3" +
            "a4d488f878a3797f8eb6e72c5ac02bc68ef4e209554e392cbc6c62a6bac6651081865f14453b25cc8a6e7ae7a3ed9c66" +
            "cd45cd6975255adc6ccb9f5625a1807bda4985ea13b1d8ec3acc67f8231f7b8111221f060e1b910ea128864ca7143e53" +
            "0ddca387a87da16bcaa29e30575a1201c986699c60fff9cf1a18197162286d03e3141a875af2097edb4e3d9461a28672" +
            "440706f85d67bb6b1130ffc96931c8f28a3a189b3591bb52d9db03782c10a2518114a6b0523c692e6fb953ad9fffe274" +
            "53c0f68fc6f2525e8f24f8aef0a7ba282ea798c31be1d02e19d657d2b85396f9a8ce1083fecb487869aed579b4dea104" +
            "6baf5ee9c9c276dfbb9e5c44b8732c52151e98d91a6ab2a22a21dadbbd9067758eed95b65940e1e3734767d5249e29c2" +
            "d6ecbfe74838b9452aff4c6a28799404c755be74d53a3fe50fcfe95548b84ce9f53e2ef0f50f2a97ded6ffaf22038c20" +
            "79bcf88b67e8f8839e10a4171b8dfac501a1d0c32c06d92c8d4771926aaa8c19cb612454bf5a0e323f07fa70019ca56f" +
            "850c74533c48a054d1f717fbcc309e85720ac6a9e7189c8c74f95e9510793fd02164a3f974fc066ca379703c87b473d5" +
            "ba8a9147868c53a5a9376e73babaabbf3caef767bb0a1f9092dd0280d9ebe919e597bd335a9101ea07f89264cd6cf881" +
            "469bd4c56e2f74dec89b875c1dd2dad33732f728c3807fa5b1fbc00d5bffbdd6907e947f37db18501d31b1b58f51e3e5" +
            "25a0aa9771105d4d89941d22641151163e36c87e114066bf5b567cee8772fdc4c657239300fa00b1a28dbb65dac4513d" +
            "2014ce58e05b2ad645dfbcadf4bef6d389eab11c417309444ba0aed0d27948afc66abe14bd54368c9030d1a6b0c99116" +
            "2265ee374f19118578b66fc33dab768535dbcd1127536b13d9ad8c24ad871b5dc58799a932cbccae51fa73e9fc12fafb" +
            "9956ddbcb54678403cd05468bf6456fd8f7e8b0324744802df81cf77bed9f1695a077ef6579c12eaf4f8ee7f6457310b" +
            "2135ace730e6c1fefd5afc9e25a0d790074fb3348b901d425b59f46e5a7b57c2e575dbec31c1b11f06610464f17a6e50" +
            "7a4b66bd32d0e18098290824fcc7cb9d0f6774a3ef839f5c2bd82ae1e33f295afcd31f951744bd5f143ba89ec6a233c4" +
            "9785e4ff39e41fd2406737f24154130d8bc7169d84b3a7d64155a9d1d2af1edff09a360374ce27983e7e5690878e7bad" +
            "39e7364a53fd8fd49d6fdefbd71fb591a1982f21ca0db5bb71c62a7e03289b57060a0abdc5e651a20ae92fe3fecd740e" +
            "09fe7356b037e7dcc4bb1c63fbe16d9f9182df15a4a3f924ed9bd425e9f4743e5bacb3af6120724b613eb9e454f90d77" +
            "fcf7deb24fcc108b5b7709450764d3354b13e233715d18e145d51683af4ee5ce71822c5123fd001980f0abcdd9ac77ed" +
            "7a3097059ef889cf2893cb2f8a6509ca684ee6ba814d4859978469d643438ced74209f8e2c4a93cdbea8be01759dca32" +
            "c4c694570340ced08fa081e5393887f5805a1fccfc666f8e3e8933a7b294cb0f755ee52dbe47f287a04d768733c5d1c8" +
            "93aeac6240f73943316b043eecf33ce5cf0da351cfd4d90b7278ada74f8a7623e6463a600dbe7426e2a6781e156f4de5" +
            "f0c477c742de9a099500cdf72723ddf696a0d4abc689d8461483eeb34b015b11cd761a7a6d6cfa6f0184d88a4681100b" +
            "40e15f6be3c9df4b316c008b104718678a162984ba39dcc306e6822b2a5b6bce86f034ec6c3db0c4cbd216cb1aa75e6c" +
            "f4244d9add931f89485dc3ec8f0ca039562d5e80d9fb5e525202def3dd77c99d6eebe31d7c4edbddf478671810e25f06" +
            "cdfb5adddc5042bcb3435206c74037578d22a76c03e866f84f7e3ce36f8b9b9574e1b0bbbbf75031d28d8ae5c5e7d250" +
            "7c2e6c9d48f885a1b572553d23644735a22e71a98614352bf69627e139bf9bd2c2f740a3a7c736db890a5f0ae458ced0" +
            "6bbcfc3bbba80888562f6a5222604bba0dd9d6becc4f96c19967278849e42b928fb57df7de0495f283f72e3b63047431" +
            "8ba2735f7a35f84d75280f15"
    }
}
