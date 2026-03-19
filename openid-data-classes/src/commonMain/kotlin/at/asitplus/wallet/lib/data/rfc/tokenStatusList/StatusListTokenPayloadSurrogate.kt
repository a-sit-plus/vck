package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDurationFormatSerializer
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
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
    @SerialName(SerialNames.SUBJECT)
    @CborLabel(CborLabels.SUBJECT)
    val subject: UniformResourceIdentifier,
    @SerialName(SerialNames.ISSUED_AT)
    @CborLabel(CborLabels.ISSUED_AT)
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,
    @SerialName(SerialNames.EXPIRATION_TIME)
    @CborLabel(CborLabels.EXPIRATION_TIME)
    @Serializable(with = InstantLongSerializer::class)
    val expirationTime: Instant? = null,

    /**
     * JSON: JsonNumber
     * CBOR: Unsigned integer (Major Type 0)
     */
    @SerialName(SerialNames.TIME_TO_LIVE)
    @CborLabel(CborLabels.TIME_TO_LIVE)
    @Serializable(with = PositiveDurationFormatSerializer::class)
    val timeToLive: PositiveDuration? = null,

    /**
     * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html
     *
     * REQUIRED*. MUST NOT be present if [identifierList] is present
     * The status_list (status list) claim MUST specify the Status List
     * conforming to the rules outlined in Section 4.1.
     */
    @SerialName(SerialNames.STATUS_LIST)
    @CborLabel(CborLabels.STATUS_LIST)
    val statusList: StatusList? = null,

    /**
     * specification: ISO18013-5
     * Conforming to the rules defined in 12.3.6
     * REQUIRED*. MUST NOT be present if [statusList] is present
     *
     * Only defined for CBOR!
     */
    @SerialName(SerialNames.IDENTIFIER_LIST)
    @CborLabel(CborLabels.IDENTIFIER_LIST)
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

    data object CborLabels {
        const val SUBJECT = 2L
        const val ISSUED_AT = 6L
        const val EXPIRATION_TIME = 4L
        const val TIME_TO_LIVE = 65534L
        const val STATUS_LIST = 65533L
        const val IDENTIFIER_LIST = 65530L
    }

    data object SerialNames {
        const val SUBJECT = "sub"
        const val ISSUED_AT = "iat"
        const val EXPIRATION_TIME = "exp"
        const val TIME_TO_LIVE = "ttl"
        const val STATUS_LIST = "status_list"
        const val IDENTIFIER_LIST = "identifier_list"
    }
}
