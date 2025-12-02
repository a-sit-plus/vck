package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtIdentifierListClaim
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
     * 65533 (status list): REQUIRED*. The claim MUST specify the Status List conforming
     * to the rules outlined in Section 4.2.
     * Must not be used when [identifierList] is present
     */
    @CborLabel(CwtStatusListClaim.Specification.CLAIM_KEY)
    @SerialName(CwtStatusListClaim.Specification.CLAIM_NAME)
    val statusList: CwtStatusListClaim? = null,

    /**
     * 65530 (identifier list): REQUIRED*. The claim MUST specify the Identifier List conforming
     * to the rules outlined in ISO 18013-5 12.3.6
     * Must not be used when [statusList] is present
     */
    @CborLabel(CwtIdentifierListClaim.Specification.CLAIM_KEY)
    @SerialName(CwtIdentifierListClaim.Specification.CLAIM_NAME)
    val identifierList: CwtIdentifierListClaim? = null,
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
        statusList = if (statusListTokenPayload.revocationList is StatusList) CwtStatusListClaim(
            statusListTokenPayload.revocationList
        ) else null,
        identifierList = if (statusListTokenPayload.revocationList is IdentifierList) CwtIdentifierListClaim(
            statusListTokenPayload.revocationList
        ) else null,
    )

    fun toStatusListTokenPayload() =
        when {
            statusList != null -> StatusListTokenPayload(
                subject = subject.uri!!,
                issuedAt = issuedAt.instant,
                expirationTime = expirationTime?.instant,
                timeToLive = timeToLive?.positiveDuration,
                revocationList = statusList.statusList,
            )

            identifierList != null -> StatusListTokenPayload(
                subject = subject.uri!!,
                issuedAt = issuedAt.instant,
                expirationTime = expirationTime?.instant,
                timeToLive = timeToLive?.positiveDuration,
                revocationList = identifierList.identifierList,
            )

            else -> throw IllegalArgumentException("Unsupported status list token payload")
        }
}

