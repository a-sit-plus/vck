@file:UseSerializers(TransactionDataEntrySerializer::class, UrlSerializer::class)

package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.ktor.http.*
import io.ktor.util.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Implements "Transaction Data entries as defined in D3.1: UC Specification WP3"
 * leveraging upcoming changes to OpenID4VP `https://github.com/openid/OpenID4VP/pull/197`
 */
interface TransactionDataEntry {
    val type: String
}

@Serializable
data class QesAuthorization private constructor(
    val signatureQualifier: String? = null,
    val credentialId: String? = null,
    val documentDigest: List<DocumentDigestEntry>,
    val processID: String? = null,
) : TransactionDataEntry {
    override val type: String = "qes_authorization"

    @Serializable
    data class DocumentDigestEntry private constructor(
        val label: String,
        val hash: String? = null, // base64 encoded octet representation using "hashAlgorithmOID"
        val hashAlgorithmOid: String? = null,
        val documentLocationUri: Url? = null,
        val documentLocationMethod: DocumentLocationMethod? = null,
        val dtbsr: String? = null,
        val dtbsrHashAlgorithmOid: String? = null,
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
        companion object {
            fun create(
                label: String,
                hash: String?,
                hashAlgorithmOid: String?,
                documentLocationUri: Url?,
                documentLocationMethod: DocumentLocationMethod?,
                dtbsr: String?,
                dtbsrHashAlgorithmOid: String?,
            ): KmmResult<DocumentDigestEntry> =
                kotlin.runCatching {
                    require(hash != null || dtbsr != null)
                    require(hashAlgorithmOid iff hash)
                    require(dtbsrHashAlgorithmOid iff dtbsr)
                    require(documentLocationUri?.toString() iff hash)
                    require(documentLocationMethod?.toString() iff documentLocationUri?.toString())
                    DocumentDigestEntry(
                        label = label,
                        hash = hash,
                        hashAlgorithmOid = hashAlgorithmOid,
                        documentLocationUri = documentLocationUri,
                        documentLocationMethod = documentLocationMethod,
                        dtbsr = dtbsr,
                        dtbsrHashAlgorithmOid = dtbsrHashAlgorithmOid,
                    )
                }.wrap()

        }
    }

    @Serializable
    data class DocumentLocationMethod private constructor(
        val documentAccessMode: String,
        val oneTimePassword: String? = null,
    ) {
        companion object {
            /**
            * If “document_access_mode” is “OTP”, “oneTimePassword” must be
            * present.
            */
            fun create(documentAccessMode: String, oneTimePassword: String?) : KmmResult<DocumentLocationMethod> =
                runCatching {
                require(oneTimePassword == null || documentAccessMode != "OTP")
                DocumentLocationMethod(
                    documentAccessMode = documentAccessMode,
                    oneTimePassword = oneTimePassword
                )
            }.wrap()
        }
    }

    companion object {
        /**
         * At least one of the mentioned parameters must be present:
         *  “signatureQualifier” or “credentialID”
         */
        fun create(
            signatureQualifier: String?,
            credentialId: String?,
            documentDigest: List<DocumentDigestEntry>,
            processID: String?,
        ): KmmResult<TransactionDataEntry> =
            runCatching {
                require(signatureQualifier != null || credentialId != null)
                QesAuthorization(
                    signatureQualifier = signatureQualifier,
                    credentialId = credentialId,
                    documentDigest = documentDigest,
                    processID = processID,
                )
            }.wrap()
    }
}

@Serializable
data class QCertCreationAcceptance(
    val qcTermsConditionsUri: String,
    val qcHash: String,
    val qcHashAlgorithmOID: String,
) : TransactionDataEntry {
    override val type: String = "qcert_creation_acceptance"
}


/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
object TransactionDataEntrySerializer : KSerializer<TransactionDataEntry> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("TransactionDataEntrySerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: TransactionDataEntry) {
        val jsonString = vckJsonSerializer.encodeToString(PolymorphicSerializer(TransactionDataEntry::class), value)
        val base64String = jsonString.encodeBase64()
        encoder.encodeString(base64String)
    }

    override fun deserialize(decoder: Decoder): TransactionDataEntry {
        val base64String = decoder.decodeString()
        val jsonString = base64String.decodeBase64String()
        return vckJsonSerializer.decodeFromString(PolymorphicSerializer(TransactionDataEntry::class), jsonString)
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
private infix fun String?.iff(other: String?): Boolean = (this != null && other != null) or (this == null && other == null)