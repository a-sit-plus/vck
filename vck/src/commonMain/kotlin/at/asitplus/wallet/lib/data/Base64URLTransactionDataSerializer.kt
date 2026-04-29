package at.asitplus.wallet.lib.data

import at.asitplus.openid.TransactionData
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
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
        joseCompliantSerializer.decodeFromString(
            TransactionData.serializer(),
            decoder.decodeString().decodeToByteArray(Base64UrlStrict).decodeToString()
        )

    override fun serialize(encoder: Encoder, value: TransactionData) {
        val jsonString = joseCompliantSerializer.encodeToString(TransactionData.serializer(), value)
        val base64URLString = jsonString.encodeToByteArray().encodeToString(Base64UrlStrict)
        encoder.encodeString(base64URLString)
    }
}

fun TransactionDataBase64Url.toTransactionData(): TransactionData =
    joseCompliantSerializer.decodeFromJsonElement(Base64URLTransactionDataSerializer, this)

fun TransactionData.toBase64UrlJsonString(): TransactionDataBase64Url = joseCompliantSerializer.parseToJsonElement(
    joseCompliantSerializer.encodeToString(
        Base64URLTransactionDataSerializer,
        this
    )
) as TransactionDataBase64Url

fun TransactionData.digest(digest: Digest): ByteArray = toBase64UrlJsonString().digest(digest)
