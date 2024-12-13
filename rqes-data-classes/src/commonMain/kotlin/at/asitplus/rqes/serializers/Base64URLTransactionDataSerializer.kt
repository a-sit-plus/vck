package at.asitplus.rqes.serializers

import at.asitplus.rqes.collection_entries.RqesTransactionData
import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
object Base64URLTransactionDataSerializer : KSerializer<RqesTransactionData> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64URLTransactionDataSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): RqesTransactionData {
        val jsonString = decoder.decodeString()
        val base64URLString = jsonString.decodeToByteArray(Base64UrlStrict).decodeToString()
        return rdcJsonSerializer.decodeFromString<RqesTransactionData>(base64URLString)
    }

    override fun serialize(encoder: Encoder, value: RqesTransactionData) {
        val jsonString = rdcJsonSerializer.encodeToString<RqesTransactionData>(value)
        val base64URLString = jsonString.encodeToByteArray().encodeToString(Base64UrlStrict)
        encoder.encodeString(base64URLString)
    }
}