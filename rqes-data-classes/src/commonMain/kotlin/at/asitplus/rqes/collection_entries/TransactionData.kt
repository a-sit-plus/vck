package at.asitplus.rqes.collection_entries

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.rqes.enums.SignatureQualifier
import at.asitplus.signum.indispensable.asn1.ObjectIdSerializer
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * Implements "Transaction Data entries as defined in D3.1: UC Specification WP3"
 * leveraging upcoming changes to [OpenID4VP](https://github.com/openid/OpenID4VP/pull/197)
 */
@Serializable
sealed class TransactionData {

    /**
     * D3.1: UC Specification WP3:
     * Transaction data entry used to authorize a qualified electronic signature
     */
    @ConsistentCopyVisibility
    @Serializable
    @SerialName("qes_authorization")
    data class QesAuthorization private constructor(
        /**
         * CSC: OPTIONAL.
         * Identifier of the signature type to be created, e.g. 'eu_eidas_qes'
         * to denote a Qualified Electronic Signature according to eIDAS.
         */
        @SerialName("signatureQualifier")
        val signatureQualifier: SignatureQualifier? = null,

        /**
         * CSC: OPTIONAL.
         * The unique identifier associated to the credential
         */
        @SerialName("credentialID")
        val credentialID: String? = null,

        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * An array composed of entries for every
         * document to be signed (SD). This
         * applies for both cases, where a
         * document is signed, or a digest is
         * signed. Every entry is [RqesDocumentDigestEntry]
         *
         * !!! Currently not compatible with the CSC definition of documentDigests
         */
        @SerialName("documentDigests")
        val documentDigests: List<RqesDocumentDigestEntry>,

        /**
         * D3.1: UC Specification WP3: OPTIONAL.
         * An opaque value used by the QTSP to
         * internally link the transaction to this
         * request. The parameter is not supposed
         * to contain a human-readable value
         */
        @SerialName("processID")
        val processID: String? = null,
    ) : TransactionData() {

        /**
         * D3.1: UC Specification WP3:
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
                signatureQualifier: SignatureQualifier?,
                credentialId: String?,
                documentDigest: List<RqesDocumentDigestEntry>,
                processID: String?,
            ): KmmResult<TransactionData> =
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

    /**
     * D3.1: UC Specification WP3:
     * Transaction data entry used to gather the user’s consent to the terms of
     * service of the Verifier (e.g. the QTSP)
     */
    @Serializable
    @SerialName("qcert_creation_acceptance")
    data class QCertCreationAcceptance(
        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * URL that points to a human-readable
         * terms of service document for the end
         * user that describes a contractual
         * relationship between the end-user and
         * the Qualified Trust Service Provider
         * The value of this field MUST
         * point to a document which is
         * accessible and displayable by the
         * Wallet
         */
        @SerialName("QC_terms_conditions_uri")
        val qcTermsConditionsUri: String,

        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * String containing the base64-encoded
         * octet-representation of applying the
         * algorithm from
         * [qcHashAlgorithmOid] to the octet-
         * representation of the document
         * referenced by [qcTermsConditionsUri]
         */
        @SerialName("QC_hash")
        @Serializable(ByteArrayBase64Serializer::class)
        val qcHash: ByteArray,

        /**
         * D3.1: UC Specification WP3: REQUIRED.
         * String containing the
         * OID of the hash algorithm used
         * to generate the hash listed in
         * [qcHash]
         */
        @SerialName("QC_hashAlgorithmOID")
        @Serializable(ObjectIdSerializer::class)
        val qcHashAlgorithmOid: ObjectIdentifier,
    ) : TransactionData() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as QCertCreationAcceptance

            if (qcTermsConditionsUri != other.qcTermsConditionsUri) return false
            if (!qcHash.contentEquals(other.qcHash)) return false
            if (qcHashAlgorithmOid != other.qcHashAlgorithmOid) return false

            return true
        }

        override fun hashCode(): Int {
            var result = qcTermsConditionsUri.hashCode()
            result = 31 * result + qcHash.contentHashCode()
            result = 31 * result + qcHashAlgorithmOid.hashCode()
            return result
        }
    }
}


