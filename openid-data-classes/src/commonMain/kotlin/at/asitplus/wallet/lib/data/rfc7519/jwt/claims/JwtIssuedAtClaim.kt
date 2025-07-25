package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import kotlinx.datetime.Instant
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * 4.1.6.  "iat" (Issued At) Claim
 *
 *    The "iat" (issued at) claim identifies the time at which the JWT was
 *    issued.  This claim can be used to determine the age of the JWT.  Its
 *    value MUST be a number containing a NumericDate value.  Use of this
 *    claim is OPTIONAL.
 */
@Serializable
@JvmInline
value class JwtIssuedAtClaim(val numericDate: NumericDate) {
    val instant: Instant
        get() = numericDate.instant

    companion object {
        operator fun invoke(instant: Instant) = JwtIssuedAtClaim(NumericDate(instant))
    }

    data object Specification {
        const val CLAIM_NAME = "iat"
    }
}

