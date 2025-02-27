@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package at.asitplus.wallet.lib

import at.asitplus.wallet.lib.data.rfc1950.CompressionMethod
import at.asitplus.wallet.lib.data.rfc1950.CompressionMethodAndFlags
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.MemScope
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArrayOf
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import platform.Foundation.NSData
import platform.Foundation.NSDataCompressionAlgorithmZlib
import platform.Foundation.NSError
import platform.Foundation.compressedDataUsingAlgorithm
import platform.Foundation.create
import platform.Foundation.decompressedDataUsingAlgorithm

actual class DefaultZlibService actual constructor() : ZlibService {

    actual override fun compress(input: ByteArray): ByteArray? {
        memScoped {
            val data = toData(input)
            val errorPointer = alloc<ObjCObjectVar<NSError?>>()
            val compressed = data.compressedDataUsingAlgorithm(NSDataCompressionAlgorithmZlib, errorPointer.ptr)
            // for debug reasons: println(errorPointer.value)
            // The iOS SDK implements Raw Deflate, so it
            // does not prepend the ZLIB header 0x78 0x9C,
            // and also skips the ADLER32 checksum as a trailer,
            // but other implementations need this!
            val byteArray = compressed?.toByteArray() ?: return null
            val zlibHeader = byteArrayOf(0x78.toByte(), 0x9C.toByte())
            return zlibHeader + byteArray + input.adler32checksum()
        }
    }

    /**
     * Calculates the ADLER-32 checksum of the input:
     * s1 is the sum of all bytes modulo 65521,
     * s2 is the sum of all s1 values modulo 65521,
     * the output is both values concatenated as 16 bit values.
     * https://www.rfc-editor.org/rfc/rfc1950
     */
    private fun ByteArray.adler32checksum(): ByteArray {
        var s1: UInt = 1U
        var s2: UInt = 0U
        this.forEach {
            s1 = (it.toUByte() + s1).mod(65521U)
            s2 = (s2 + s1).mod(65521U)
        }
        return s2.toByteArray(2) + s1.toByteArray(2)
    }

    /**
     * Converts UInt to byte array, in network order (most significant bytes first)
     */
    private fun UInt.toByteArray(size: Int = 4): ByteArray =
        ByteArray(size) { i -> (this.toLong() shr (i * 8)).toByte() }.reversedArray()

    actual override fun decompress(input: ByteArray): ByteArray? {
        memScoped {
            // The iOS SDK implements Raw Inflate,
            // so this only works if the compression method DEFLATE is used.
            val data = toData(
                if (input.size > 1 && CompressionMethodAndFlags(input[0]).compressionMethod.value == CompressionMethod.DEFLATE.toByte()) {
                    input.drop(2).toByteArray()
                } else {
                    TODO("Implement fallback to generic zlib decompression algorithm.")
                },
            )
            val errorPointer = alloc<ObjCObjectVar<NSError?>>()
            val decompressed = data.decompressedDataUsingAlgorithm(
                NSDataCompressionAlgorithmZlib,
                errorPointer.ptr
            )
            // for debug reasons: println(errorPointer.value)
            return decompressed?.toByteArray()
        }
    }
}

@Suppress("NOTHING_TO_INLINE")
inline fun MemScope.toData(array: ByteArray): NSData =
    NSData.create(
        bytes = allocArrayOf(array),
        length = array.size.toULong()
    )

// from https://github.com/mirego/trikot.foundation/pull/41/files
fun NSData.toByteArray(): ByteArray {
    return this.bytes?.let {
        val dataPointer: CPointer<ByteVar> = it.reinterpret()
        ByteArray(this.length.toInt()) { index -> dataPointer[index] }
    } ?: ByteArray(0)
}
