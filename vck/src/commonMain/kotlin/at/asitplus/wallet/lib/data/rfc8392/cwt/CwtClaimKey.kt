package at.asitplus.wallet.lib.data.rfc8392.cwt

import kotlin.jvm.JvmInline

/**
 * specification: https://www.rfc-editor.org/rfc/rfc8392
 *
 * To keep CWTs as small as possible, the Claim Keys are represented
 * using integers or text strings.  Section 4 summarizes all keys used
 * to identify the claims defined in this document.
 */
sealed interface CwtClaimKey {
    @JvmInline
    value class IntegerClaimKey(val value: Long) : CwtClaimKey {
        override fun toString() = "$value"
    }

    @JvmInline
    value class TextStringClaimKey(val value: String) : CwtClaimKey {
        override fun toString() = value
    }

    companion object {
        operator fun invoke(value: Int) = IntegerClaimKey(value.toLong())
        operator fun invoke(value: Long) = IntegerClaimKey(value)
        operator fun invoke(value: String) = TextStringClaimKey(value)
    }
}