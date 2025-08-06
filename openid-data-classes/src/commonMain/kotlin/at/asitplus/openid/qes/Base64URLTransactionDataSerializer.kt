package at.asitplus.openid.qes

import at.asitplus.openid.TransactionData
import at.asitplus.openid.odcJsonSerializer
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

/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
object Base64URLTransactionDataSerializer : KSerializer<TransactionData> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64URLTransactionDataSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): TransactionData =
        odcJsonSerializer.decodeFromString(
            PolymorphicSerializer(TransactionData::class),
            decoder.decodeString().decodeToByteArray(Base64UrlStrict).decodeToString()
        )

    override fun serialize(encoder: Encoder, value: TransactionData) {
        val jsonString = odcJsonSerializer.encodeToString(PolymorphicSerializer(TransactionData::class), value)
        val base64URLString = jsonString.encodeToByteArray().encodeToString(Base64UrlStrict)
        encoder.encodeString(base64URLString)
    }
}