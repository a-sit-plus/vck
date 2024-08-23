@file:UseSerializers(TransactionDataEntrySerializer::class, UrlSerializer::class)

package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.PolymorphicSerializer
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
//interface TransactionDataEntry {
//    val type: String
//}

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

        @Serializable
        data class DocumentDigestEntry private constructor(
            val label: String,
            val hash: String? = null, // base64 encoded octet representation using "hashAlgorithmOID"
            val hashAlgorithmOID: String? = null,
            @SerialName("documentLocations_uri") //errorous in test vector - changed for test case
            val documentLocationUri: Url? = null,
            @SerialName("documentLocation_method")
            val documentLocationMethod: DocumentLocationMethod? = null,
            val dtbsr: String? = null,
            val dtbsrHashAlgorithmOID: String? = null,
        ) {
            /**
             * If in each of the following bullet points one of the mentioned parameters is
             * present, the other must be present:
             *  “hash” and “hashAlgorithmOID”
             *  “documentLocation_uri” and “documentLocation_method”
             *  “dtbsr” and “dtbsrHashAlgorithmOID”
             * In each of the following bullet points at least one of the mentioned
             * parameters must be present:
             *  “hash” or “dtbsr”
             */
            init {
                require(hash != null || dtbsr != null)
                require(hashAlgorithmOID iff hash)
                require(dtbsrHashAlgorithmOID iff dtbsr)
                require(documentLocationUri?.toString() iff hash)
                require(documentLocationMethod?.toString() iff documentLocationUri?.toString())
            }

            companion object {
                /**
                 * Safe way to construct the object as init throws
                 */
                fun create(
                    label: String,
                    hash: String?,
                    hashAlgorithmOID: String?,
                    documentLocationUri: Url?,
                    documentLocationMethod: DocumentLocationMethod?,
                    dtbsr: String?,
                    dtbsrHashAlgorithmOID: String?,
                ): KmmResult<DocumentDigestEntry> =
                    kotlin.runCatching {
                        DocumentDigestEntry(
                            label = label,
                            hash = hash,
                            hashAlgorithmOID = hashAlgorithmOID,
                            documentLocationUri = documentLocationUri,
                            documentLocationMethod = documentLocationMethod,
                            dtbsr = dtbsr,
                            dtbsrHashAlgorithmOID = dtbsrHashAlgorithmOID,
                        )
                    }.wrap()

            }
        }

        @Serializable
        @SerialName("documentLocation_method")
        data class DocumentLocationMethod private constructor(
            val method: Method,  //this is potentially a mistake in the draft spec vs test vector
            val oneTimePassword: String? = null,
        ) {
            /**
             * If “document_access_mode” is “OTP”, “oneTimePassword” must be
             * present.
             */
            init {
                require(oneTimePassword == null || method.type != "OTP")
            }

            @Serializable
            data class Method(
                @SerialName("type")
                val type: String
            )

            companion object {
                fun create(method: Method, oneTimePassword: String?): KmmResult<DocumentLocationMethod> =
                    runCatching {
                        DocumentLocationMethod(
                            method = method,
                            oneTimePassword = oneTimePassword
                        )
                    }.wrap()
            }
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
            "qes_authorization" -> vckJsonSerializer.decodeFromJsonElement<TransactionDataEntry.QesAuthorization>(jsonObject)
            "qcert_creation_acceptance" -> vckJsonSerializer.decodeFromJsonElement<TransactionDataEntry.QCertCreationAcceptance>(jsonObject)
            else -> throw SerializationException("Unknown type: $type")
        }
    }
}

object UrlSerializer : KSerializer<Url> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("UrlSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Url = Url(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Url) {
        encoder.encodeString(value.toString())
    }

}

/**
 * Checks that either both strings are present or null
 */
private infix fun String?.iff(other: String?): Boolean =
    (this != null && other != null) or (this == null && other == null)