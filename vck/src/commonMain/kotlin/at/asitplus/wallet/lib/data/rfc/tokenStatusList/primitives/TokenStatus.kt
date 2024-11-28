package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import kotlin.jvm.JvmInline

@JvmInline
value class TokenStatus(val value: UByte) {
    constructor(value: UInt) : this(
        value.also {
            if (it > UByte.MAX_VALUE || it < UByte.MIN_VALUE) {
                throw IllegalArgumentException("Argument `value` must represent an unsigned byte.")
            }
        }.toUByte(),
    )

    object Type {
        const val VALID = 0x00u
        const val INVALID = 0x01u
        const val SUSPENDED = 0x02u
        const val APPLICATION_SPECIFIC_3 = 0x03u
        const val APPLICATION_SPECIFIC_14 = 0x0eu
        const val APPLICATION_SPECIFIC_15 = 0x0fu
    }

    val isValid: Boolean
        get() = value == Type.VALID.toUByte()
}