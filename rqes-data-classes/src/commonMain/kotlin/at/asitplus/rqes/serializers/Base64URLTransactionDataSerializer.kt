package at.asitplus.rqes.serializers

import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonElement

/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
@Deprecated("Module will be removed in the future", ReplaceWith("at.asitplus.wallet.lib.data.Base64URLTransactionDataSerializer"))
object Base64URLTransactionDataSerializer : KSerializer<TransactionData> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64URLTransactionDataSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): TransactionData =
        rdcJsonSerializer.decodeFromString(
            PolymorphicSerializer(TransactionData::class),
            decoder.decodeString().decodeToByteArray(Base64UrlStrict).decodeToString()
        )

    override fun serialize(encoder: Encoder, value: TransactionData) {
        val jsonString = rdcJsonSerializer.encodeToString(PolymorphicSerializer(TransactionData::class), value)
        val base64URLString = jsonString.encodeToByteArray().encodeToString(Base64UrlStrict)
        encoder.encodeString(base64URLString)
    }
}

@Deprecated(
    "Will be removed, only for backwards compatability",
    replaceWith = ReplaceWith("Base64URLTransactionDataSerializer")
)
object DeprecatedBase64URLTransactionDataSerializer : KSerializer<TransactionData> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64URLTransactionDataSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): TransactionData {
        val decoded = decoder.decodeString()
            .let { if (it.contains(",")) it else it.decodeToByteArray(Base64UrlStrict).decodeToString() }
        val json = rdcJsonSerializer.decodeFromString(JsonElement.serializer(), decoded)
        return rdcJsonSerializer.decodeFromJsonElement(PolymorphicSerializer(TransactionData::class), json)
    }

    override fun serialize(encoder: Encoder, value: TransactionData) {
        val jsonString = rdcJsonSerializer.encodeToString(PolymorphicSerializer(TransactionData::class), value)
        val base64URLString = jsonString.encodeToByteArray().encodeToString(Base64UrlStrict)
        encoder.encodeString(base64URLString)
    }
}