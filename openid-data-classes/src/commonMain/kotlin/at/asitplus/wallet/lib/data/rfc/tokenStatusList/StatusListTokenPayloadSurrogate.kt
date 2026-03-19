package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtIdentifierListClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtStatusListClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims.CwtTimeToLiveClaim
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDurationFormatSerializer
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtExpirationTimeClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtIssuedAtClaim
import at.asitplus.wallet.lib.data.rfc8392.cwt.claims.CwtSubjectClaim
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.cbor.CborEncoder
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
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
    @Serializable(with = PositiveDurationFormatSerializer::class)
    val timeToLive: PositiveDuration? = null,
    @SerialName("status_list")
    @CborLabel(CwtStatusListClaim.Specification.CLAIM_KEY)
    val statusList: StatusList? = null,
    @SerialName("identifier_list")
    @CborLabel(CwtIdentifierListClaim.Specification.CLAIM_KEY)
    @Serializable(with = CborOnlyIdentifierListSerializer::class)
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
        require(statusList == null || identifierList == null) { "Either StatusList or IdentifierList must be present" }
    }

    fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = subject,
        issuedAt = issuedAt,
        expirationTime = expirationTime,
        timeToLive = timeToLive,
        revocationList = statusList ?: identifierList
        ?: throw Exception("Either StatusList or IdentifierList must be present"),
    )

    internal object CborOnlyIdentifierListSerializer : KSerializer<IdentifierList> {
        private val delegate = IdentifierList.Companion.serializer()
        override val descriptor = delegate.descriptor

        override fun serialize(encoder: Encoder, value: IdentifierList) {
            if (encoder !is CborEncoder) {
                throw SerializationException("IdentifierList is only supported in CBOR")
            }
            delegate.serialize(encoder, value)
        }

        override fun deserialize(decoder: Decoder): IdentifierList {
            if (decoder !is CborDecoder) {
                throw SerializationException("IdentifierList is only supported in CBOR")
            }
            return delegate.deserialize(decoder)
        }
    }
}
