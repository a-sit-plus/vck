package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusListClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtTimeToLiveClaim
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtExpirationTimeClaim
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIssuedAtClaim
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtSubjectClaim
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-list-token-in-jwt-fo
 */
@Serializable
internal data class JwtStatusListTokenPayload(
    /**
     * sub: REQUIRED. As generally defined in RFC7519. The sub (subject) claim MUST specify the
     * URI of the Status List Token. The value MUST be equal to that of the uri claim contained in
     * the status_list claim of the Referenced Token.
     */
    @SerialName(JwtSubjectClaim.Specification.CLAIM_NAME)
    val subject: JwtSubjectClaim,
    /**
     * iat: REQUIRED. As generally defined in RFC7519. The iat (issued at) claim MUST specify the
     * time at which the Status List Token was issued.
     */
    @SerialName(JwtIssuedAtClaim.Specification.CLAIM_NAME)
    val issuedAt: JwtIssuedAtClaim,
    /**
     * exp: RECOMMENDED. As generally defined in RFC7519. The exp (expiration time) claim, if
     * present, MUST specify the time at which the Status List Token is considered expired by the
     * Status Issuer.
     */
    @SerialName(JwtExpirationTimeClaim.Specification.CLAIM_NAME)
    val expirationTime: JwtExpirationTimeClaim? = null,
    /**
     * ttl: RECOMMENDED. The ttl (time to live) claim, if present, MUST specify the maximum amount of
     * time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy
     * SHOULD be retrieved. The value of the claim MUST be a positive number encoded in JSON as a
     * number.
     */
    @SerialName(JwtTimeToLiveClaim.Specification.CLAIM_NAME)
    val timeToLive: JwtTimeToLiveClaim? = null,
    /**
     * status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List
     * conforming to the rules outlined in Section 4.1.
     */
    @SerialName(JwtStatusListClaim.Specification.CLAIM_NAME)
    val statusList: JwtStatusListClaim,
) {
    constructor(statusListTokenPayload: StatusListTokenPayload) : this(
        subject = JwtSubjectClaim(statusListTokenPayload.subject),
        issuedAt = JwtIssuedAtClaim(statusListTokenPayload.issuedAt),
        expirationTime = statusListTokenPayload.expirationTime?.let {
            JwtExpirationTimeClaim(it)
        },
        timeToLive = statusListTokenPayload.timeToLive?.let {
            JwtTimeToLiveClaim(it)
        },
        statusList = when (statusListTokenPayload.revocationList) {
            is StatusList -> JwtStatusListClaim(statusListTokenPayload.revocationList)
            is IdentifierList -> throw IllegalArgumentException("Identifier list not supported for JWT")
        }
    )


    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject.uri!!,
        issuedAt = issuedAt.instant,
        expirationTime = expirationTime?.instant,
        timeToLive = timeToLive?.positiveDuration,
        revocationList = statusList.statusList,
    )
}

