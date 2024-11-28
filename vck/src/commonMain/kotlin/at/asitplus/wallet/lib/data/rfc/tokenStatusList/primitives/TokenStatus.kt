package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlin.jvm.JvmInline

/**
 *  7. Status Types
 *
 * This document defines statuses of Referenced Tokens as Status Type values. A status describes
 * the state, mode, condition or stage of an entity that is represented by the Referenced Token.
 * A Status List can not represent multiple statuses per Referenced Token. If the Status List
 * contains more than one bit per token (as defined by bits in the Status List), then the whole
 * value of bits MUST describe one value. Status Types MUST have a numeric value between 0 and 255
 * for their representation in the Status List. The issuer of the Status List MUST choose an
 * adequate bits (bit size) to be able to describe the required Status Types for its application.
 */
@JvmInline
value class TokenStatus(val value: UByte) {
    constructor(value: UInt) : this(
        value.also {
            if (it > UByte.MAX_VALUE || it < UByte.MIN_VALUE) {
                throw IllegalArgumentException("Argument `value` must represent an unsigned byte.")
            }
        }.toUByte(),
    )

    val isValid: Boolean
        get() = this == Valid
    val isInvalid: Boolean
        get() = this == Invalid

    companion object {
        val Valid = TokenStatus(Specification.VALID)
        val Invalid = TokenStatus(Specification.INVALID)
        val Suspended = TokenStatus(Specification.SUSPENDED)
        val ApplicationSpecific3 = TokenStatus(Specification.APPLICATION_SPECIFIC_3)
        val ApplicationSpecific14 = TokenStatus(Specification.APPLICATION_SPECIFIC_14)
        val ApplicationSpecific15 = TokenStatus(Specification.APPLICATION_SPECIFIC_15)
    }

    object Specification {
        const val VALID = 0x00u
        const val INVALID = 0x01u
        const val SUSPENDED = 0x02u
        const val APPLICATION_SPECIFIC_3 = 0x03u
        const val APPLICATION_SPECIFIC_14 = 0x0eu
        const val APPLICATION_SPECIFIC_15 = 0x0fu
    }
}