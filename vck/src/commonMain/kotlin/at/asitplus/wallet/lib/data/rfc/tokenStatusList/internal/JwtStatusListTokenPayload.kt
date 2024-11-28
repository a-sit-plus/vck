package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtTimeToLivePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.JwtTimeToLive
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtSubjectPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@ExperimentalUnsignedTypes
@Serializable
internal data class JwtStatusListTokenPayload(
    @SerialName(JwtSubjectPayloadClaimSpecification.NAME) val subject: StringOrURI,
    @SerialName(JwtIssuedAtPayloadClaimSpecification.NAME) val issuedAt: NumericDate,
    @SerialName(JwtExpirationTimePayloadClaimSpecification.NAME) val expirationTime: NumericDate? = null,
    @SerialName(JwtTimeToLivePayloadClaimSpecification.NAME) val timeToLive: JwtTimeToLive? = null,
    @SerialName(JwtStatusListPayloadClaimSpecification.NAME) val statusList: StatusList,
) {
    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject,
        issuedAt = issuedAt,
        expirationTime = expirationTime,
        timeToLive = timeToLive?.let {
            JwtTimeToLive(PositiveDuration(it.duration))
        },
        statusList = statusList,
    )

    companion object {
        fun StatusListTokenPayload.toJwtStatusListTokenPayload() = JwtStatusListTokenPayload(
            subject = subject,
            issuedAt = issuedAt,
            expirationTime = expirationTime,
            timeToLive = timeToLive?.let {
                JwtTimeToLive(PositiveDuration(it.duration))
            },
            statusList = statusList,
        )
    }
}

