package at.asitplus.wallet.lib.data.rfc1950

import at.asitplus.wallet.lib.data.rfc1950.primitives.Nibble
import kotlin.jvm.JvmInline

/**
 *       CMF (Compression Method and flags)
 *          This byte is divided into a 4-bit compression method and a 4-
 *          bit information field depending on the compression method.
 *
 *             bits 0 to 3  CM     Compression method
 *             bits 4 to 7  CINFO  Compression info
 */
@JvmInline
value class CompressionMethodAndFlags(val value: Byte) {
    val compressionMethod: Nibble
        get() = Nibble.coerceFromByte(value)

    val compressionInfo: Nibble
        get() = Nibble.coerceFromByte(value.toUByte().toInt().shr(4).toByte())
}