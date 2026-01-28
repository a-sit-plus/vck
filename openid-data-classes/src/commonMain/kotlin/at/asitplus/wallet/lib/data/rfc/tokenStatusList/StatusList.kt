package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSizeValueSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder

/**
 * specification: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-06.html#name-status-list
 * Status list in its compressed form.
 */
@Serializable
data class StatusList(
    @SerialName("lst")
    @Serializable(with = StatusListCompressedSerializer::class)
    val compressed: ByteArray,
    @SerialName("bits")
    @Serializable(with = TokenStatusBitSizeValueSerializer::class)
    val statusBitSize: TokenStatusBitSize,
    @SerialName("aggregation_uri")
    val aggregationUri: String? = null,
) : RevocationList() {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as StatusList

        if (!compressed.contentEquals(other.compressed)) return false
        if (statusBitSize != other.statusBitSize) return false
        if (aggregationUri != other.aggregationUri) return false

        return true
    }

    override fun hashCode(): Int {
        var result = compressed.contentHashCode()
        result = 31 * result + statusBitSize.hashCode()
        result = 31 * result + (aggregationUri?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "StatusList(" +
                "aggregationUri=$aggregationUri, " +
                "statusBitSize=$statusBitSize, " +
                "compressed=${compressed.encodeToString(Base64Strict)}" +
                ")"
    }

    /**
     * Format-aware serializer for [StatusList.compressed].
     * JSON -> base64url string, CBOR -> byte string.
     */
    internal object StatusListCompressedSerializer : KSerializer<ByteArray> {
        private val byteArraySerializer = ByteArraySerializer()

        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("StatusListCompressed", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: ByteArray) {
            when (encoder) {
                is JsonEncoder -> ByteArrayBase64UrlSerializer.serialize(encoder, value)
                else -> encoder.encodeSerializableValue(byteArraySerializer, value)
            }
        }

        override fun deserialize(decoder: Decoder): ByteArray = when (decoder) {
            is JsonDecoder -> ByteArrayBase64UrlSerializer.deserialize(decoder)
            else -> decoder.decodeSerializableValue(byteArraySerializer)
        }
    }

}




