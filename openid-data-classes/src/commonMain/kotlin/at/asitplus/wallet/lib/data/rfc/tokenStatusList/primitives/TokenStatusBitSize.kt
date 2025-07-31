package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable

@Serializable(with = TokenStatusBitSizeValueSerializer::class)
enum class TokenStatusBitSize(val value: UInt, val maxValue: UInt) {
    ONE(1u, 1u), TWO(2u, 3u), FOUR(4u, 15u), EIGHT(8u, 255u);

    companion object {
        fun valueOf(value: UInt) = entries.firstOrNull {
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