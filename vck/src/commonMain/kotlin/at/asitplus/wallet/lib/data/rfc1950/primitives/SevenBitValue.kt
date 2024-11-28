package at.asitplus.wallet.lib.data.rfc1950.primitives

import kotlin.experimental.and
import kotlin.jvm.JvmInline

@JvmInline
value class SevenBitValue(val value: Byte) {
    companion object {
        @Suppress("MemberVisibilityCanBePrivate")
        const val MAX_VALUE = 0b111_1111
        @Suppress("MemberVisibilityCanBePrivate")
        const val MIN_VALUE = 0

        fun validate(value: Byte) {
            if(value !in MIN_VALUE..MAX_VALUE) {
                throw IllegalArgumentException("Argument `value` must only set the seven least significant bits.")
            }
        }

        fun coerceFromByte(value: Byte) = SevenBitValue(value.and(MAX_VALUE.toByte()))
    }
    init {
        validate(value)
    }
}