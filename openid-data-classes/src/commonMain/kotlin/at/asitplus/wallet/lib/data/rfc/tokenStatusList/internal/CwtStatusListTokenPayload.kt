package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLiveClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtExpirationTimeClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuedAtClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectClaim
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborLabel

/**
 * [Specification](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-list-token-in-cwt-fo)
 * The Status List Token MUST be encoded as a "CBOR Web Token (CWT)" according to RFC8392.
 */
@Serializable
internal data class CwtStatusListTokenPayload(
    /**
     * 2 (subject): REQUIRED. As generally defined in RFC8392. The subject claim MUST specify the
     * URI of the Status List Token. The value MUST be equal to that of the uri claim contained in
     * the status_list claim of the Referenced Token.
     */
    @CborLabel(CwtSubjectClaim.Specification.CLAIM_KEY)
    @SerialName(CwtSubjectClaim.Specification.CLAIM_NAME)
    val subject: CwtSubjectClaim,
    /**
     * 6 (issued at): REQUIRED. As generally defined in RFC8392. The issued at claim MUST specify
     * the time at which the Status List Token was issued.
     */
    @CborLabel(CwtIssuedAtClaim.Specification.CLAIM_KEY)
    @SerialName(CwtIssuedAtClaim.Specification.CLAIM_NAME)
    val issuedAt: CwtIssuedAtClaim,
    /**
     * 4 (expiration time): RECOMMENDED. As generally defined in RFC8392. The expiration time claim,
     * if present, MUST specify the time at which the Status List Token is considered expired by
     * its issuer.
     */
    @CborLabel(CwtExpirationTimeClaim.Specification.CLAIM_KEY)
    @SerialName(CwtExpirationTimeClaim.Specification.CLAIM_NAME)
    val expirationTime: CwtExpirationTimeClaim? = null,
    /**
     * 65534 (time to live): RECOMMENDED. Unsigned integer (Major Type 0). The time to live claim, if
     * present, MUST specify the maximum amount of time, in seconds, that the Status List Token can
     * be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST
     * be a positive number.
     */
    @CborLabel(CwtTimeToLiveClaim.Specification.CLAIM_KEY)
    @SerialName(CwtTimeToLiveClaim.Specification.CLAIM_NAME)
    val timeToLive: CwtTimeToLiveClaim? = null,
    /**
     * 65533 (status list): REQUIRED. The status list claim MUST specify the Status List conforming
     * to the rules outlined in Section 4.2.
     */
    @CborLabel(CwtStatusListClaim.Specification.CLAIM_KEY)
    @SerialName(CwtStatusListClaim.Specification.CLAIM_NAME)
    val statusList: CwtStatusListClaim,
) {
    constructor(statusListTokenPayload: StatusListTokenPayload) : this(
        subject = CwtSubjectClaim(statusListTokenPayload.subject),
        issuedAt = CwtIssuedAtClaim(statusListTokenPayload.issuedAt),
        expirationTime = statusListTokenPayload.expirationTime?.let {
            CwtExpirationTimeClaim(it)
        },
        timeToLive = statusListTokenPayload.timeToLive?.let {
            CwtTimeToLiveClaim(it)
        },
        statusList = CwtStatusListClaim(
            statusListTokenPayload.statusList
        ),
    )

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject.uri!!,
        issuedAt = issuedAt.instant,
        expirationTime = expirationTime?.instant,
        timeToLive = timeToLive?.positiveDuration,
        statusList = statusList.statusList,
    )
}

