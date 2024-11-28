package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtTimeToLivePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.MissingPayloadClaimException
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtSubjectPayloadClaimSpecification

/**
 * The following content applies to the JWT Claims Set:
 *
 * sub: REQUIRED. As generally defined in [RFC7519]. The sub (subject) claim MUST specify the URI of the Status List Token. The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token.
 *
 * iat: REQUIRED. As generally defined in [RFC7519]. The iat (issued at) claim MUST specify the time at which the Status List Token was issued.
 *
 * exp: OPTIONAL. As generally defined in [RFC7519]. The exp (expiration time) claim, if present, MUST specify the time at which the Status List Token is considered expired by the Status Issuer.
 *
 * ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a positive number encoded in JSON as a number.
 *
 * status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List conforming to the rules outlined in Section 4.1.
 */
@ExperimentalUnsignedTypes
interface OptionalJwtStatusListTokenPayloadClaimsProvider :
    JwtSubjectPayloadClaimSpecification.ClaimProvider,
    JwtIssuedAtPayloadClaimSpecification.ClaimProvider,
    JwtExpirationTimePayloadClaimSpecification.ClaimProvider,
    JwtTimeToLivePayloadClaimSpecification.ClaimProvider,
    JwtStatusListPayloadClaimSpecification.ClaimProvider {

    val containsStatusListTokenPayload: Boolean
        get() = sub != null && iat != null && status_list != null

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = sub
            ?: throw MissingPayloadClaimException(JwtSubjectPayloadClaimSpecification.NAME),
        issuedAt = iat
            ?: throw MissingPayloadClaimException(JwtIssuedAtPayloadClaimSpecification.NAME),
        expirationTime = exp,
        timeToLive = ttl,
        statusList = status_list ?: throw MissingPayloadClaimException(
            JwtStatusListPayloadClaimSpecification.NAME
        ),
    )
}

