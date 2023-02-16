package at.asitplus.wallet.lib

import kotlin.experimental.and
import kotlin.experimental.inv
import kotlin.experimental.or

private fun getByteIndex(i: Long) = (i / 8).toInt()
private fun getBitIndex(i: Long) = (i % 8).toInt()

private fun List<Byte>.getBit(index: Long): Boolean =
    if (index < 0) throw IndexOutOfBoundsException("index = $index")
    else kotlin.runCatching {
        this[getByteIndex(index)].getBit(getBitIndex(index))
    }.getOrElse { false }

private fun Byte.getBit(index: Int): Boolean =
    if (index < 0 || index > 7) throw IndexOutOfBoundsException("bit index $index out of bounds.")
    else (((1 shl index).toByte() and this) != 0.toByte())

/**
 * Pure Kotlin Bit Set created by throwing a bunch of extension functions at a MutableList<Byte>
 */
class KmmBitSet constructor(private val bytes: MutableList<Byte>) {
    constructor(nbits: Long = 0) : this(
        if (nbits < 0) throw IllegalArgumentException("a bit set of size $nbits makes no sense")
        else
            MutableList(getByteIndex(nbits) + 1) { 0.toByte() })

    operator fun get(index: Long): Boolean = bytes.getBit(index)

    fun nextSetBit(fromIndex: Long): Long {
        if (fromIndex < 0) throw IndexOutOfBoundsException("fromIndex = $fromIndex")

        val byteIndex = getByteIndex(fromIndex)

        if (byteIndex >= bytes.size) return -1
        else {
            bytes.subList(byteIndex, bytes.size).let { list ->
                val startIndex = getBitIndex(fromIndex).toLong()
                for (i: Long in startIndex until list.size.toLong() * 8L) {
                    if (list.getBit(i)) return byteIndex.toLong() * 8L + i
                }
            }
            return -1
        }
    }

    operator fun set(index: Long, value: Boolean) {
        val byteIndex = getByteIndex(index)
        while (bytes.size <= byteIndex) bytes.add(0)
        val byte = bytes[byteIndex]
        bytes[byteIndex] =
            if (value) {
                ((1 shl getBitIndex(index)).toByte() or byte)
            } else
                ((1 shl getBitIndex(index)).toByte().inv() and byte)
    }

    fun length(): Long = highestSetIndex() + 1L

    fun toByteArray(): ByteArray {
        return if (bytes.isEmpty() || highestSetIndex() == -1L) byteArrayOf()
        else bytes.subList(0, getByteIndex(highestSetIndex()) + 1).toTypedArray().toByteArray()
    }

    private fun highestSetIndex(): Long {
        for (i: Long in bytes.size.toLong() * 8L - 1L downTo 0L) {
            if (bytes.getBit(i)) return i
        }
        return -1L
    }

    fun toBitString() = toByteArray().toBitString()
}

fun ByteArray.toBitSet(): KmmBitSet = KmmBitSet(toMutableList())


/**
 * Returns a view of this bit set's memory layout.
 *
 * Note that this representation conflicts with the usual binary representation of a bit-set's
 * underlying byte array for the following reason:
 *
 * Printing a byte array usually shows the MS*Byte* at the right-most position, but each byte's MS*Bit*
 * at a byte's individual left-most position, leading to bit and byte indices running in opposing directions.
 *
 * The string representation returned by this function can simply be interpreted as a list of boolean values
 * accessible by a monotonic index running in one direction.
 *
 * See the following illustration of memory layout vs. bit string:
 * ```
 * ┌──────────────────────────────┐
 * │                              │
 * │                              │ Addr: 2
 * │    0  0  0  0  1  1  0  1    │
 * │ ◄─23─22─21─20─19─18─17─16─┐  │
 * │                           │  │
 * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
 * │                           │  │
 * │ ┌─────────────────────────┘  │ Addr: 1
 * │ │  1  0  0  0  1  0  0  0    │
 * │ └─15─14─12─12─11─10──9──8─┐  │
 * │                           │  │
 * ├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ┤
 * │                           │  │
 * │ ┌─────────────────────────┘  │ Addr: 0
 * │ │  1  0  1  1  0  1  1  1    │
 * │ └──7──6──5──4──3──2──1──0──────index─◄─
 * │                              │
 * └──────────────────────────────┘
 *```
 * This leads to the following bit string:
 * 11101101 00010001 10110000
 */
fun ByteArray.toBitString(): String =
    joinToString(separator = " ") {
        it.toUByte().toString(2).reversed().let { str ->
            (0 until 8).map { kotlin.runCatching { str[it] }.getOrElse { '0' } }.toCharArray()
                .concatToString()
        }
    }
