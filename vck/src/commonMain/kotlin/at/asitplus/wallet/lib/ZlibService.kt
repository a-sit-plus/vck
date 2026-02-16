package at.asitplus.wallet.lib

import okio.Buffer
import okio.Deflater
import okio.DeflaterSink
import okio.Inflater
import okio.InflaterSource

interface ZlibService {

    fun compress(input: ByteArray): ByteArray?

    fun decompress(input: ByteArray): ByteArray?

}

class DefaultZlibService : ZlibService {

    companion object {
        internal const val MAX_DECOMPRESSED_SIZE = 5 * 1024 * 1024L
        private const val READ_CHUNK_SIZE = 8 * 1024L
    }

    override fun compress(input: ByteArray): ByteArray? = runCatching {
        val uncompressed = Buffer().write(input)
        val compressed = Buffer()
        val deflaterSink = DeflaterSink(compressed, Deflater())
        try {
            deflaterSink.write(uncompressed, uncompressed.size)
        } finally {
            deflaterSink.close()
        }
        compressed.readByteArray()
    }.getOrNull()

    override fun decompress(input: ByteArray): ByteArray? = runCatching {
        val compressed = Buffer().write(input)
        val decompressed = Buffer()
        val inflaterSource = InflaterSource(compressed, Inflater())
        try {
            while (true) {
                val bytesRead = inflaterSource.read(decompressed, READ_CHUNK_SIZE)
                if (bytesRead == -1L) break
                require(decompressed.size <= MAX_DECOMPRESSED_SIZE) {
                    "Decompression exceeded $MAX_DECOMPRESSED_SIZE bytes, is: ${decompressed.size}."
                }
            }
        } finally {
            inflaterSource.close()
        }
        decompressed.readByteArray()
    }.getOrNull()
}
