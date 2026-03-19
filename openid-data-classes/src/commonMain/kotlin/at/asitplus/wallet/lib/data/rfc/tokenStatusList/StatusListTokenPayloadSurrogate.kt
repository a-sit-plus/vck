package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtIdentifierListClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLiveClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDurationSecondsULongSerializer
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtExpirationTimeClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuedAtClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectClaim
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.CborLabel
import kotlin.time.Instant

/**
 * Helper class necessary to correctly map Cbor-labels for [statusList] and [identifierList]
 * without having to write the entire serializer manually
 */
@Serializable
data class StatusListTokenPayloadSurrogate(
    @SerialName("sub")
    @CborLabel(CwtSubjectClaim.Specification.CLAIM_KEY)
    val subject: UniformResourceIdentifier,
    @SerialName("iat")
    @CborLabel(CwtIssuedAtClaim.Specification.CLAIM_KEY)
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,
    @SerialName("exp")
    @CborLabel(CwtExpirationTimeClaim.Specification.CLAIM_KEY)
    @Serializable(with = InstantLongSerializer::class)
    val expirationTime: Instant? = null,
    @SerialName("ttl")
    @CborLabel(CwtTimeToLiveClaim.Specification.CLAIM_KEY)
    @Serializable(with = PositiveDurationSecondsULongSerializer::class)
    val timeToLive: PositiveDuration? = null,
    @SerialName("status_list")
    @CborLabel(CwtStatusListClaim.Specification.CLAIM_KEY)
    val statusList: StatusList? = null,
    @SerialName("identifier_list")
    @CborLabel(CwtIdentifierListClaim.Specification.CLAIM_KEY)
    val identifierList: IdentifierList? = null,
) {
    constructor(statusListTokenPayload: StatusListTokenPayload) : this(
        subject = statusListTokenPayload.subject,
        issuedAt = statusListTokenPayload.issuedAt,
        expirationTime = statusListTokenPayload.expirationTime,
        timeToLive = statusListTokenPayload.timeToLive,
        statusList = statusListTokenPayload.revocationList as? StatusList,
        identifierList = statusListTokenPayload.revocationList as? IdentifierList,
    )

    init {
        require(statusList == null || identifierList == null) {"Either StatusList or IdentifierList must be present"}
    }

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject,
        issuedAt = issuedAt,
        expirationTime = expirationTime,
        timeToLive = timeToLive,
        revocationList = statusList ?: identifierList ?: throw Exception("Either StatusList or IdentifierList must be present"),
    )


    object StatusListTokenSurrogateSerializer :
        TransformingSerializerTemplate<StatusListTokenPayload, StatusListTokenPayloadSurrogate>(
            parent = StatusListTokenPayloadSurrogate.serializer(),
            encodeAs = {
                StatusListTokenPayloadSurrogate(it)
            },
            decodeAs = {
                it.toStatusListTokenPayload()
            },
        )
}
