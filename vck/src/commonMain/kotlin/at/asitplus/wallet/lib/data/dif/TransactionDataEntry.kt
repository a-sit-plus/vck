@file:UseSerializers(TransactionDataEntrySerializer::class, UrlSerializer::class)

package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.ktor.util.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonPrimitive


/**
 * Implements "Transaction Data entries as defined in D3.1: UC Specification WP3"
 * leveraging upcoming changes to OpenID4VP `https://github.com/openid/OpenID4VP/pull/197`
 */
@Serializable
sealed class TransactionDataEntry {
    abstract val type: String

    @Serializable
    @SerialName("qes_authorization")
    data class QesAuthorization private constructor(
        val signatureQualifier: String? = null,
        val credentialId: String? = null,
        val documentDigests: List<DocumentDigestEntry>,
        val processID: String? = null,
    ) : TransactionDataEntry() {
        override val type: String = "qes_authorization"

        /**
         * At least one of the mentioned parameters must be present:
         *  “signatureQualifier” or “credentialID”
         */
        init {
            require(signatureQualifier != null || credentialId != null)
        }

        companion object {
            /**
             * Safe way to construct the object as init throws
             */
            fun create(
                signatureQualifier: String?,
                credentialId: String?,
                documentDigest: List<DocumentDigestEntry>,
                processID: String?,
            ): KmmResult<TransactionDataEntry> =
                runCatching {
                    QesAuthorization(
                        signatureQualifier = signatureQualifier,
                        credentialId = credentialId,
                        documentDigests = documentDigest,
                        processID = processID,
                    )
                }.wrap()
        }
    }

    @Serializable
    @SerialName("TODO")
    data class QCertCreationAcceptance(
        val qcTermsConditionsUri: String,
        val qcHash: String,
        val qcHashAlgorithmOID: String,
    ) : TransactionDataEntry() {
        override val type: String = "qcert_creation_acceptance"
    }
}


/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
object TransactionDataEntrySerializer : KSerializer<TransactionDataEntry> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("TransactionDataEntrySerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: TransactionDataEntry) {
        val jsonString = vckJsonSerializer.encodeToString(value)
        val base64String = jsonString.encodeBase64()
        encoder.encodeString(base64String)
    }

    override fun deserialize(decoder: Decoder): TransactionDataEntry {
        // Decode Base64 string to JSON string
        val jsonString = decoder.decodeString().decodeBase64String()

        // Parse the JSON string to a JSON object
        val jsonObject = vckJsonSerializer.parseToJsonElement(jsonString) as JsonObject

        // Extract the type field
        val type = jsonObject["type"]?.jsonPrimitive?.content
            ?: throw SerializationException("Missing type field in JSON")

        // Deserialize based on type
        return when (type) {
            "qes_authorization" -> vckJsonSerializer.decodeFromJsonElement<TransactionDataEntry.QesAuthorization>(
                jsonObject
            )

            "qcert_creation_acceptance" -> vckJsonSerializer.decodeFromJsonElement<TransactionDataEntry.QCertCreationAcceptance>(
                jsonObject
            )

            else -> throw SerializationException("Unknown type: $type")
        }
    }
}

