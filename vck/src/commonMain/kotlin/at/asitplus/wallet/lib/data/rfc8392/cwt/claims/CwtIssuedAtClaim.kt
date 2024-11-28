package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.6.  iat (Issued At) Claim
 *
 *    The "iat" (issued at) claim has the same meaning and processing rules
 *    as the "iat" claim defined in Section 4.1.6 of [RFC7519], except that
 *    the value is a NumericDate, as defined in Section 2 of this
 *    specification.  The Claim Key 6 is used to identify this claim.
 */
@Serializable
@JvmInline
value class CwtIssuedAtClaim(val value: NumericDate) {
    val instant: Instant
        get() = value.instant

    companion object {
        operator fun invoke(instant: Instant) = CwtIssuedAtClaim(NumericDate(instant))
    }

    data object Specification {
        const val CLAIM_NAME = "iat"
        const val CLAIM_KEY = 6L
    }
}