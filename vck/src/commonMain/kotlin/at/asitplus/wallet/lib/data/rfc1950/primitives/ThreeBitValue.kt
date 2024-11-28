package at.asitplus.wallet.lib.data.rfc1950.primitives

import kotlin.experimental.and
import kotlin.jvm.JvmInline

@JvmInline
value class ThreeBitValue(val value: Byte) {
    companion object {
        @Suppress("MemberVisibilityCanBePrivate")
        const val MAX_VALUE = 0b111
        @Suppress("MemberVisibilityCanBePrivate")
        const val MIN_VALUE = 0

        fun validate(value: Byte) {
            if(value !in MIN_VALUE..MAX_VALUE) {
                throw IllegalArgumentException("Argument `value` must only set the three least significant bits.")
            }
        }

        fun coerceFromByte(value: Byte) = ThreeBitValue(value.and(MAX_VALUE.toByte()))
    }

    init {
        validate(value)
    }
}