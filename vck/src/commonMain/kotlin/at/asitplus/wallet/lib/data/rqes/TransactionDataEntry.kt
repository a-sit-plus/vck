@file:UseSerializers(UrlSerializer::class)

package at.asitplus.wallet.lib.data.rqes

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.wallet.lib.data.dif.UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers


/**
 * Implements "Transaction Data entries as defined in D3.1: UC Specification WP3"
 * leveraging upcoming changes to [OpenID4VP](https://github.com/openid/OpenID4VP/pull/197)
 */
@Serializable
sealed class TransactionDataEntry {

    @Serializable
    @SerialName("qes_authorization")
    data class QesAuthorization private constructor(
        @SerialName("signatureQualifier")
        val signatureQualifier: String? = null,
        @SerialName("credentialID")
        val credentialID: String? = null,
        @SerialName("documentDigests")
        val documentDigests: List<DocumentDigestEntry>,
        @SerialName("processID")
        val processID: String? = null,
    ) : TransactionDataEntry() {

        /**
         * At least one of the mentioned parameters must be present:
         * - [signatureQualifier] or [credentialID]
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
        val qcHash: @Serializable(ByteArrayBase64Serializer::class) ByteArray,
        @SerialName("QC_hashAlgorithmOID")
        val qcHashAlgorithmOID: @Serializable(ObjectIdSerializer::class) ObjectIdentifier,
    ) : TransactionDataEntry() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as QCertCreationAcceptance

            if (qcTermsConditionsUri != other.qcTermsConditionsUri) return false
            if (!qcHash.contentEquals(other.qcHash)) return false
            if (qcHashAlgorithmOID != other.qcHashAlgorithmOID) return false

            return true
        }

        override fun hashCode(): Int {
            var result = qcTermsConditionsUri.hashCode()
            result = 31 * result + qcHash.contentHashCode()
            result = 31 * result + qcHashAlgorithmOID.hashCode()
            return result
        }
    }
}


