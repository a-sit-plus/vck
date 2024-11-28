package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLivePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtStatusListPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims.JwtTimeToLivePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TimeToLive
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtExpirationTimePayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtIssuedAtPayloadClaimSpecification
import at.asitplus.wallet.lib.data.rfc7519.jwt.claims.JwtSubjectPayloadClaimSpecification
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
internal data class StatusListTokenPayloadSurrogate(
    @SerialName(JwtSubjectPayloadClaimSpecification.NAME)
    @CborLabel(CwtSubjectPayloadClaimSpecification.KEY)
    val subject: StringOrURI,
    @SerialName(JwtIssuedAtPayloadClaimSpecification.NAME)
    @CborLabel(CwtIssuedAtPayloadClaimSpecification.KEY)
    val issuedAt: NumericDate,
    @SerialName(JwtExpirationTimePayloadClaimSpecification.NAME)
    @CborLabel(CwtExpirationTimePayloadClaimSpecification.KEY)
    val expirationTime: ExpirationTime? = null,
    @SerialName(JwtTimeToLivePayloadClaimSpecification.NAME)
    @CborLabel(CwtTimeToLivePayloadClaimSpecification.KEY)
    val timeToLive: TimeToLive? = null,
    @SerialName(JwtStatusListPayloadClaimSpecification.NAME)
    @CborLabel(CwtStatusListPayloadClaimSpecification.KEY)
    val statusList: StatusList,
) {
    constructor(
        statusListTokenPayload: StatusListTokenPayload,
    ): this(
        subject = statusListTokenPayload.subject,
        issuedAt = statusListTokenPayload.issuedAt,
        expirationTime = statusListTokenPayload.expirationTime,
        timeToLive = statusListTokenPayload.timeToLive,
        statusList = statusListTokenPayload.statusList,
    )

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject,
        issuedAt = issuedAt,
        expirationTime = expirationTime,
        timeToLive = timeToLive,
        statusList = statusList,
    )

    companion object {
        fun fromStatusListTokenPayload(statusListTokenPayload: StatusListTokenPayload) =
            statusListTokenPayload.run {
                StatusListTokenPayloadSurrogate(
                    subject = subject,
                    issuedAt = issuedAt,
                    expirationTime = expirationTime,
                    timeToLive = timeToLive,
                    statusList = statusList,
                )
            }

        init {
            // TODO: Move to tests?
            // Sanity check that the serial names are compatible between formats
            listOf(
                "status" to mapOf(
                    "Json" to JwtSubjectPayloadClaimSpecification.NAME,
                    "Cbor" to CwtSubjectPayloadClaimSpecification.NAME,
                ),
                "issuedAt" to mapOf(
                    "Json" to JwtIssuedAtPayloadClaimSpecification.NAME,
                    "Cbor" to CwtIssuedAtPayloadClaimSpecification.NAME,
                ),
                "expirationTime" to mapOf(
                    "Json" to JwtExpirationTimePayloadClaimSpecification.NAME,
                    "Cbor" to CwtExpirationTimePayloadClaimSpecification.NAME,
                ),
                "timeToLive" to mapOf(
                    "Json" to JwtTimeToLivePayloadClaimSpecification.NAME,
                    "Cbor" to CwtTimeToLivePayloadClaimSpecification.NAME,
                ),
                "statusList" to mapOf(
                    "Json" to JwtStatusListPayloadClaimSpecification.NAME,
                    "Cbor" to CwtStatusListPayloadClaimSpecification.NAME,
                ),
            ).forEach { (memberName, serialLabels) ->
                if (serialLabels.values.distinct().size != 1) {
                    throw IllegalStateException(
                        "Member `$memberName` has different serial names between the following formats: [${
                            serialLabels.keys.joinToString(
                                ", "
                            ) { it }
                        }]"
                    )
                }
            }
        }
    }
}