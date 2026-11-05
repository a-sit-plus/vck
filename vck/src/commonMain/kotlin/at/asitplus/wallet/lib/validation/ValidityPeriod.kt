package at.asitplus.wallet.lib.validation

import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.agent.validation.TimeScope
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import kotlin.time.Instant

/**
 * The validity period an artifact claims, from [notBefore] to [notAfter], either of which may be absent, by which its
 * timeliness is decided, see [check].
 */
data class ValidityPeriod(
    val notBefore: Instant?,
    val notAfter: Instant?,
) {
    /**
     * Passed if [TimeScope.now] is within this period, taking [TimeScope.timeLeeway] into account, otherwise failed
     * with a [TimelinessException] carrying this period, whose message names the [artifact].
     */
    fun check(timeScope: TimeScope, artifact: String): CheckOutcome = with(timeScope) {
        fun failed(message: String) = Failed(TimelinessException(message, now, notBefore, notAfter))
        when {
            notBefore != null && notBefore.isTooLate() -> failed("The $artifact is not yet valid")
            notAfter != null && notAfter.isTooEarly() -> failed("The $artifact is expired")
            else -> Passed
        }
    }
}

/** `nbf` to `exp` of the issuer-signed JWT (draft-ietf-oauth-sd-jwt-vc-19, 2.2.2.3). */
val VerifiableCredentialSdJwt.validityPeriod: ValidityPeriod
    get() = ValidityPeriod(notBefore, expiration)

/** `validFrom` to `validUntil` of the `validityInfo` (ISO/IEC 18013-5:2021, 9.1.2.4). */
val MobileSecurityObject.validityPeriod: ValidityPeriod
    get() = ValidityPeriod(validityInfo.validFrom, validityInfo.validUntil)

/**
 * The intersection of `nbf` to `exp` of the JWT and `issuanceDate` to `expirationDate` of the credential (W3C VC Data
 * Model 1.1, *JWT decoding*), which the semantics of a VC-JWT require to agree.
 */
val VerifiableCredentialJws.validityPeriod: ValidityPeriod
    get() = ValidityPeriod(
        notBefore = maxOf(notBefore, vc.issuanceDate),
        notAfter = listOfNotNull(expiration, vc.expirationDate).minOrNull(),
    )
