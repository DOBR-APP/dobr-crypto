package app.dobr.crypto

import java.io.Closeable
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Streaming AES-256-GCM file format used for every item and thumbnail.
 *
 * Layout:
 *   header  = magic (4) | chunkSize (4) | noncePrefix (8)
 *   chunk_i = AES-GCM(plain_i) with 16 byte tag
 *
 * Each chunk uses nonce = noncePrefix || i (big endian, 4 bytes) and binds
 * header || i || lastFlag as associated data. Reordering, swapping files or
 * cutting chunks off the end all fail authentication.
 *
 * Fixed size chunks also give cheap random access, which video seeking needs.
 */
object ChunkedCipher {
    const val MAGIC = 0x44425231 // "DBR1"
    const val DEFAULT_CHUNK = 64 * 1024
    const val TAG_LEN = 16
    const val HEADER_LEN = 16
    private const val MIN_CHUNK = 1024
    private const val MAX_CHUNK = 16 * 1024 * 1024

    private val random = SecureRandom()

    fun encrypt(
        key: ByteArray,
        input: InputStream,
        output: OutputStream,
        chunkSize: Int = DEFAULT_CHUNK,
    ): Long {
        require(key.size == 32) { "AES-256 key required" }
        require(chunkSize in MIN_CHUNK..MAX_CHUNK)
        val prefix = ByteArray(8).also { random.nextBytes(it) }
        val header = ByteBuffer.allocate(HEADER_LEN).putInt(MAGIC).putInt(chunkSize).put(prefix).array()
        output.write(header)

        val secret = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        var current = ByteArray(chunkSize)
        var next = ByteArray(chunkSize)
        var currentLen = readFully(input, current)
        var index = 0
        var total = 0L
        while (true) {
            val nextLen = if (currentLen < chunkSize) 0 else readFully(input, next)
            val last = nextLen == 0
            cipher.init(Cipher.ENCRYPT_MODE, secret, GCMParameterSpec(TAG_LEN * 8, nonce(prefix, index)))
            cipher.updateAAD(aad(header, index, last))
            output.write(cipher.doFinal(current, 0, currentLen))
            total += currentLen
            if (last) break
            val swap = current; current = next; next = swap
            currentLen = nextLen
            index++
            if (index < 0) throw IOException("File too large")
        }
        current.fill(0); next.fill(0)
        output.flush()
        return total
    }

    fun encryptBytes(key: ByteArray, plain: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(plain.size + HEADER_LEN + TAG_LEN * 2)
        encrypt(key, plain.inputStream(), out)
        return out.toByteArray()
    }

    fun decrypt(key: ByteArray, input: InputStream, output: OutputStream): Long {
        val data = DataInputStream(input)
        val header = ByteArray(HEADER_LEN)
        try {
            data.readFully(header)
        } catch (e: java.io.EOFException) {
            throw GeneralSecurityException("Truncated header")
        }
        val (chunkSize, prefix) = parseHeader(header)
        val secret = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val full = chunkSize + TAG_LEN
        var current = ByteArray(full)
        var next = ByteArray(full)
        var currentLen = readFully(data, current)
        if (currentLen < TAG_LEN) throw GeneralSecurityException("Missing data")
        var index = 0
        var total = 0L
        while (true) {
            val nextLen = if (currentLen < full) 0 else readFully(data, next)
            val last = nextLen == 0
            cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(TAG_LEN * 8, nonce(prefix, index)))
            cipher.updateAAD(aad(header, index, last))
            val plain = cipher.doFinal(current, 0, currentLen)
            output.write(plain)
            total += plain.size
            plain.fill(0)
            if (last) break
            if (nextLen < TAG_LEN) throw GeneralSecurityException("Truncated chunk")
            val swap = current; current = next; next = swap
            currentLen = nextLen
            index++
        }
        output.flush()
        return total
    }

    fun decryptBytes(key: ByteArray, cipherText: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(maxOf(0, cipherText.size - HEADER_LEN))
        decrypt(key, cipherText.inputStream(), out)
        return out.toByteArray()
    }

    fun decryptFile(key: ByteArray, file: File): ByteArray = file.inputStream().buffered().use { input ->
        val out = java.io.ByteArrayOutputStream(maxOf(0, file.length().toInt() - HEADER_LEN))
        decrypt(key, input, out)
        out.toByteArray()
    }

    internal fun parseHeader(header: ByteArray): Pair<Int, ByteArray> {
        val buf = ByteBuffer.wrap(header)
        if (buf.int != MAGIC) throw GeneralSecurityException("Not a Dobr file")
        val chunkSize = buf.int
        if (chunkSize !in MIN_CHUNK..MAX_CHUNK) throw GeneralSecurityException("Bad chunk size")
        val prefix = ByteArray(8).also { buf.get(it) }
        return chunkSize to prefix
    }

    internal fun nonce(prefix: ByteArray, index: Int): ByteArray =
        ByteBuffer.allocate(12).put(prefix).putInt(index).array()

    internal fun aad(header: ByteArray, index: Int, last: Boolean): ByteArray =
        ByteBuffer.allocate(header.size + 5).put(header).putInt(index).put(if (last) 1 else 0).array()

    private fun readFully(input: InputStream, buffer: ByteArray): Int {
        var read = 0
        while (read < buffer.size) {
            val n = input.read(buffer, read, buffer.size - read)
            if (n < 0) break
            read += n
        }
        return read
    }
}

/**
 * Random access reader over a [ChunkedCipher] file. Decrypts one chunk at a
 * time and keeps the most recent chunk cached for sequential reads.
 */
class ChunkedFileReader(file: File, key: ByteArray) : Closeable {
    private val raf = RandomAccessFile(file, "r")
    private val secret = SecretKeySpec(key.copyOf(), "AES")
    private val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    private val header = ByteArray(ChunkedCipher.HEADER_LEN)
    private val chunkSize: Int
    private val prefix: ByteArray
    private val chunkCount: Int
    val plainLength: Long

    private var cachedIndex = -1
    private var cached: ByteArray = ByteArray(0)

    init {
        try {
            raf.readFully(header)
            val parsed = ChunkedCipher.parseHeader(header)
            chunkSize = parsed.first
            prefix = parsed.second
            val body = raf.length() - ChunkedCipher.HEADER_LEN
            val full = (chunkSize + ChunkedCipher.TAG_LEN).toLong()
            if (body < ChunkedCipher.TAG_LEN) throw GeneralSecurityException("Missing data")
            val count = (body + full - 1) / full
            val lastLen = body - (count - 1) * full - ChunkedCipher.TAG_LEN
            if (lastLen < 0 || count > Int.MAX_VALUE) throw GeneralSecurityException("Corrupt file")
            chunkCount = count.toInt()
            plainLength = (count - 1) * chunkSize + lastLen
        } catch (e: Exception) {
            raf.close()
            throw e
        }
    }

    fun read(position: Long, buffer: ByteArray, offset: Int, length: Int): Int {
        if (position >= plainLength || length == 0) return if (length == 0) 0 else -1
        val index = (position / chunkSize).toInt()
        val chunk = chunk(index)
        val within = (position - index.toLong() * chunkSize).toInt()
        val n = minOf(length, chunk.size - within)
        System.arraycopy(chunk, within, buffer, offset, n)
        return n
    }

    private fun chunk(index: Int): ByteArray {
        if (index == cachedIndex) return cached
        val full = chunkSize + ChunkedCipher.TAG_LEN
        val start = ChunkedCipher.HEADER_LEN + index.toLong() * full
        val len = minOf(full.toLong(), raf.length() - start).toInt()
        val data = ByteArray(len)
        raf.seek(start)
        raf.readFully(data)
        val last = index == chunkCount - 1
        cipher.init(Cipher.DECRYPT_MODE, secret, GCMParameterSpec(ChunkedCipher.TAG_LEN * 8, ChunkedCipher.nonce(prefix, index)))
        cipher.updateAAD(ChunkedCipher.aad(header, index, last))
        cached.fill(0)
        cached = cipher.doFinal(data)
        cachedIndex = index
        return cached
    }

    /**
     * A plain sequential stream over the decrypted contents, for decoders that
     * want an InputStream. Supports mark and reset. Streams share this reader,
     * so use them one at a time on one thread.
     */
    fun stream(): InputStream = object : InputStream() {
        private var pos = 0L
        private var markPos = 0L
        private val one = ByteArray(1)

        override fun read(): Int = if (read(one, 0, 1) <= 0) -1 else one[0].toInt() and 0xff

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            val n = this@ChunkedFileReader.read(pos, b, off, len)
            if (n > 0) pos += n
            return n
        }

        override fun skip(n: Long): Long {
            val k = n.coerceIn(0L, plainLength - pos)
            pos += k
            return k
        }

        override fun available(): Int = (plainLength - pos).coerceIn(0L, Int.MAX_VALUE.toLong()).toInt()
        override fun markSupported() = true
        override fun mark(readlimit: Int) { markPos = pos }
        override fun reset() { pos = markPos }
    }

    override fun close() {
        cached.fill(0)
        raf.close()
    }
}
