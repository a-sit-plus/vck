package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLivePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.MissingPayloadClaimException
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectPayloadClaimSpecification

/**
 * 2 (subject): REQUIRED. As generally defined in [RFC8392]. The subject claim MUST specify the URI of the Status List Token. The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token.
 *
 * 6 (issued at): REQUIRED. As generally defined in [RFC8392]. The issued at claim MUST specify the time at which the Status List Token was issued.
 *
 * 4 (expiration time): OPTIONAL. As generally defined in [RFC8392]. The expiration time claim, if present, MUST specify the time at which the Status List Token is considered expired by its issuer.
 *
 * 65534 (time to live): OPTIONAL. Unsigned integer (Major Type 0). The time to live claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a positive number.
 *
 * 65533 (status list): REQUIRED. The status list claim MUST specify the Status List conforming to the rules outlined in Section 4.2.
 */
@ExperimentalUnsignedTypes
interface OptionalCwtStatusListTokenPayloadClaimsProvider :
    CwtSubjectPayloadClaimSpecification.ClaimProvider, CwtIssuedAtPayloadClaimSpecification.ClaimProvider,
    CwtExpirationTimePayloadClaimSpecification.ClaimProvider,
    CwtTimeToLivePayloadClaimSpecification.ClaimProvider, CwtStatusListPayloadClaimSpecification.ClaimProvider {

    val containsStatusListTokenPayload: Boolean
        get() = sub != null && iat != null && status_list != null

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = sub ?: throw MissingPayloadClaimException(CwtSubjectPayloadClaimSpecification.toNameWithKeyString()),
        issuedAt = iat ?: throw MissingPayloadClaimException(CwtIssuedAtPayloadClaimSpecification.toNameWithKeyString()),
        expirationTime = exp,
        timeToLive = ttl,
        statusList = status_list ?: throw MissingPayloadClaimException(
            CwtStatusListPayloadClaimSpecification.toNameWithKeyString()),
    )
}