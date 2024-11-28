package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable

@Serializable(with = TokenStatusBitSizeValueSerializer::class)
enum class TokenStatusBitSize {
    ONE, TWO, FOUR, EIGHT;

    val value: Int
        get() = when (this) {
            ONE -> 1
            TWO -> 2
            FOUR -> 4
            EIGHT -> 8
        }

    val mask: UByte
        get() = when(this) {
            ONE -> 0b1u
            TWO -> 0b11u
            FOUR -> 0xfu
            EIGHT -> 0xffu
        }

    companion object {
        fun valueOf(value: Int) = entries.firstOrNull {
            it.value == value
        } ?: throw IllegalArgumentException(
            "Argument `value` must be one of: [${
                entries.joinToString(", ") {
                    it.value.toString()
                }
            }]",
        )
    }
}