package at.asitplus.wallet.lib

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.util.zip.Deflater
import java.util.zip.DeflaterInputStream
import java.util.zip.InflaterInputStream

actual class DefaultZlibService actual constructor() : ZlibService {

    /**
     * 5 MB seems to be safe for a max. inflated byte array
     */
    private val MAX_DECOMPRESSED_SIZE = 5 * 1024 * 1024

    actual override fun compress(input: ByteArray): ByteArray? {
        return DeflaterInputStream(input.inputStream(), Deflater(Deflater.DEFAULT_COMPRESSION)).readBytes()
    }

    /**
     * Safely decompresses ZLIB encoded bytes, with max size [MAX_DECOMPRESSED_SIZE]
     */
    actual override fun decompress(input: ByteArray): ByteArray? {
        return InflaterInputStream(input.inputStream()).readBytes().also {
            val inflaterStream = InflaterInputStream(input.inputStream())
            val outputStream = ByteArrayOutputStream(DEFAULT_BUFFER_SIZE)
            inflaterStream.copyTo(outputStream)
            outputStream.toByteArray()
        }
    }

    // Adapted from kotlin-stdblib's kotlin.io.IOStreams.kt
    private fun InflaterInputStream.copyTo(out: OutputStream, bufferSize: Int = DEFAULT_BUFFER_SIZE): Long {
        var bytesCopied: Long = 0
        val buffer = ByteArray(bufferSize)
        var bytes = read(buffer)
        while (bytes >= 0) {
            out.write(buffer, 0, bytes)
            bytesCopied += bytes
            bytes = read(buffer)
            // begin patch
            if (bytesCopied > MAX_DECOMPRESSED_SIZE) {
                throw IllegalArgumentException("Decompression exceeded $MAX_DECOMPRESSED_SIZE bytes, is: $bytesCopied! Input must be invalid.")
            }
            // end patch
        }
        return bytesCopied
    }

}