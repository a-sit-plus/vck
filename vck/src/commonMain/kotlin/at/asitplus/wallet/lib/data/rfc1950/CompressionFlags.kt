package at.asitplus.wallet.lib.data.rfc1950

import at.asitplus.wallet.lib.data.rfc1950.primitives.FiveBitValue
import at.asitplus.wallet.lib.data.rfc1950.primitives.Nibble
import at.asitplus.wallet.lib.data.rfc1950.primitives.TwoBitValue
import kotlin.experimental.and
import kotlin.jvm.JvmInline

/**
 *       FLG (FLaGs)
 *          This flag byte is divided as follows:
 *
 *             bits 0 to 4  FCHECK  (check bits for CMF and FLG)
 *             bit  5       FDICT   (preset dictionary)
 *             bits 6 to 7  FLEVEL  (compression level)
 */
@JvmInline
value class CompressionFlags(val value: Byte) {
    /**
     *          The FCHECK value must be such that CMF and FLG, when viewed as
     *          a 16-bit unsigned integer stored in MSB order (CMF*256 + FLG),
     *          is a multiple of 31.
     */
    val checkBits: FiveBitValue
        get() = FiveBitValue.coerceFromByte(value)

    /**
     *       FDICT (Preset dictionary)
     *          If FDICT is set, a DICT dictionary identifier is present
     *          immediately after the FLG byte. The dictionary is a sequence of
     *          bytes which are initially fed to the compressor without
     *          producing any compressed output. DICT is the Adler-32 checksum
     *          of this sequence of bytes (see the definition of ADLER32
     *          below).  The decompressor can use this identifier to determine
     *          which dictionary has been used by the compressor.
     */
    val hasDictionaryIdentifierAfterFlagByte: Boolean
        get() = value.and(0b0010_0000).toInt() != 0

    /**
     *       FLEVEL (Compression level)
     *          These flags are available for use by specific compression
     *          methods.  The "deflate" method (CM = 8) sets these flags as
     *          follows:
     *
     *             0 - compressor used fastest algorithm
     *             1 - compressor used fast algorithm
     *             2 - compressor used default algorithm
     *             3 - compressor used maximum compression, slowest algorithm
     *
     *          The information in FLEVEL is not needed for decompression; it
     *          is there to indicate if recompression might be worthwhile.
     */
    val compressionLevel: TwoBitValue
        get() = TwoBitValue.coerceFromByte(value.toInt().shr(6).toByte())
}