package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import kotlin.experimental.and
import kotlin.experimental.or

data class StatusListView(
    val uncompressed: ByteArray,
    val statusBitSize: TokenStatusBitSize,
) {
    fun isEmpty() = uncompressed.isEmpty()
    fun isNotEmpty() = uncompressed.isNotEmpty()

    operator fun get(index: Int) = get(index.toLong())
    operator fun get(index: Long) = getOrNull(index) ?: throw IndexOutOfBoundsException()
    fun getOrNull(index: Long): TokenStatus? {
        val tokenStatusesPerByte = Byte.SIZE_BITS / statusBitSize.value

        val byteIndex = (index / tokenStatusesPerByte).also {
            if (it > Int.MAX_VALUE) {
                throw IllegalArgumentException("Argument `index` is too big, it must be at most `Int.MAX_VALUE * bits`.")
            }
        }.toInt()
        val byte = uncompressed.getOrNull(byteIndex) ?: return null


        val statusMask = when(statusBitSize) {
            TokenStatusBitSize.ONE -> 0b1u
            TokenStatusBitSize.TWO -> 0b11u
            TokenStatusBitSize.FOUR -> 0xfu
            TokenStatusBitSize.EIGHT -> 0xffu
        }

        val lowestBitOffset = ((index % tokenStatusesPerByte) * statusBitSize.value).toInt()
        val mask = statusMask.shl(lowestBitOffset).toByte()

        val tokenStatusByte = byte.and(mask).toUByte().toInt().shr(lowestBitOffset).toUByte()

        return TokenStatus(tokenStatusByte)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as StatusListView

        if (!uncompressed.contentEquals(other.uncompressed)) return false
        if (statusBitSize != other.statusBitSize) return false

        return true
    }

    override fun hashCode(): Int {
        var result = uncompressed.contentHashCode()
        result = 31 * result + statusBitSize.hashCode()
        return result
    }

    companion object {
        /**
         * @param statusBitSize: If set to null, the smallest possible bitsize is chosen
         */
        fun fromTokenStatuses(
            tokenStatuses: List<TokenStatus>,
            statusBitSize: TokenStatusBitSize?,
        ): StatusListView {
            val highestBitByte = tokenStatuses.maxOfOrNull {
                it.value
            } ?: return StatusListView(
                uncompressed = ByteArray(0),
                statusBitSize = statusBitSize ?: TokenStatusBitSize.ONE,
            )

            val requiredBitSize = when {
                highestBitByte > 0b1111u -> TokenStatusBitSize.EIGHT
                highestBitByte > 0b11u -> TokenStatusBitSize.FOUR
                highestBitByte > 0b1u -> TokenStatusBitSize.TWO
                else -> TokenStatusBitSize.ONE
            }

            val usedBitSize = statusBitSize ?: requiredBitSize
            if(usedBitSize.value < requiredBitSize.value) {
                throw IllegalArgumentException("Argument `tokenStatuses` contains entries that do not fit into the size specified in `statusBitSize`.")
            }

            val statusesPerByte = Byte.SIZE_BITS / usedBitSize.value
            val uncompressed = tokenStatuses.chunked(statusesPerByte) { chunk ->
                chunk.map {
                    it.value.toByte()
                }.reduceIndexed { index, acc, byte ->
                    val shiftDistance = index * (Byte.Companion.SIZE_BITS / statusesPerByte)
                    val shifted = byte.toInt().shl(shiftDistance).toByte()
                    acc.or(shifted)
                }
            }.toByteArray()

            return StatusListView(
                statusBitSize = usedBitSize,
                uncompressed = uncompressed,
            )
        }
    }
}