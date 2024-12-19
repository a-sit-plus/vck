package at.asitplus.wallet.lib.data.rfc1950.primitives

import kotlin.experimental.and
import kotlin.jvm.JvmInline

@JvmInline
value class FourBitValue(val value: Byte) {
    init {
        validate(value)
    }

    companion object {
        @Suppress("MemberVisibilityCanBePrivate")
        const val MAX_VALUE = 0b1111
        @Suppress("MemberVisibilityCanBePrivate")
        const val MIN_VALUE = 0

        fun validate(value: Byte) {
            if(value !in MIN_VALUE..MAX_VALUE) {
                throw IllegalArgumentException("Argument `value` must only set the four least significant bits.")
            }
        }

        fun coerceFromByte(value: Byte) = FourBitValue(value.and(MAX_VALUE.toByte()))
    }
}