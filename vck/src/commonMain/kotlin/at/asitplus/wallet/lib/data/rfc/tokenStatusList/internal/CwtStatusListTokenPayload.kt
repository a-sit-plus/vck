package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLivePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.CwtTimeToLive
import at.asitplus.wallet.lib.data.rfc7519.primitives.ExpirationTime
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectPayloadClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborLabel

@Serializable
internal data class CwtStatusListTokenPayload(
    @CborLabel(CwtSubjectPayloadClaimSpecification.KEY)
    @SerialName(CwtSubjectPayloadClaimSpecification.NAME) val subject: StringOrURI,
    @CborLabel(CwtIssuedAtPayloadClaimSpecification.KEY)
    @SerialName(CwtIssuedAtPayloadClaimSpecification.NAME) val issuedAt: NumericDate,
    @CborLabel(CwtExpirationTimePayloadClaimSpecification.KEY)
    @SerialName(CwtExpirationTimePayloadClaimSpecification.NAME) val expirationTime: ExpirationTime? = null,
    @CborLabel(CwtTimeToLivePayloadClaimSpecification.KEY)
    @SerialName(CwtTimeToLivePayloadClaimSpecification.NAME) val timeToLive: CwtTimeToLive? = null,
    @CborLabel(CwtStatusListPayloadClaimSpecification.KEY)
    @SerialName(CwtStatusListPayloadClaimSpecification.NAME) val statusList: StatusList,
) {
    constructor(statusListTokenPayload: StatusListTokenPayload) : this(
        subject = statusListTokenPayload.subject,
        issuedAt = statusListTokenPayload.issuedAt,
        expirationTime = statusListTokenPayload.expirationTime,
        timeToLive = statusListTokenPayload.timeToLive?.let {
            CwtTimeToLive.fromTimeToLive(it)
        },
        statusList = statusListTokenPayload.statusList,
    )

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject,
        issuedAt = issuedAt,
        expirationTime = expirationTime,
        timeToLive = timeToLive,
        statusList = statusList,
    )
}

