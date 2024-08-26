@file:UseSerializers(UrlSerializer::class)

package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Implements "Transaction Data entries as defined in D3.1: UC Specification WP3"
 * leveraging upcoming changes to OpenID4VP `https://github.com/openid/OpenID4VP/pull/197`
 */
@Serializable
sealed class TransactionDataEntry {

    @Serializable
    @SerialName("qes_authorization")
    data class QesAuthorization private constructor(
        val signatureQualifier: String? = null,
        val credentialID: String? = null,
        val documentDigests: List<DocumentDigestEntry>,
        val processID: String? = null,
    ) : TransactionDataEntry() {

        /**
         * At least one of the mentioned parameters must be present:
         *  “signatureQualifier” or “credentialID”
         */
        init {
            require(signatureQualifier != null || credentialID != null)
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
                        credentialID = credentialId,
                        documentDigests = documentDigest,
                        processID = processID,
                    )
                }.wrap()
        }
    }

    @Serializable
    @SerialName("qcert_creation_acceptance")
    data class QCertCreationAcceptance(
        @SerialName("QC_terms_conditions_uri")
        val qcTermsConditionsUri: String,
        @SerialName("QC_hash")
        /**
         * Base64 encoded string
         */
        val qcHash: String,
        @SerialName("QC_hashAlgorithmOID")
        val qcHashAlgorithmOID: String,
    ) : TransactionDataEntry()
}


/**
 * According to "Transaction Data entries as defined in D3.1: UC Specification WP3" the encoding
 * is JSON and every entry is serialized to a base64 encoded string
 */
object Base64URLTransactionDataSerializer : KSerializer<TransactionDataEntry> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("Base64URLTransactionDataSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): TransactionDataEntry {
        val jsonString = decoder.decodeString()
        val base64URLString = jsonString.decodeToByteArray(Base64UrlStrict).decodeToString()
        return vckJsonSerializer.decodeFromString<TransactionDataEntry>(base64URLString)
    }

    override fun serialize(encoder: Encoder, value: TransactionDataEntry) {
        val jsonString = vckJsonSerializer.encodeToString<TransactionDataEntry>(value)
        val base64URLString = jsonString.encodeToByteArray().encodeToString(Base64UrlStrict)
        encoder.encodeString(base64URLString)
    }
}


