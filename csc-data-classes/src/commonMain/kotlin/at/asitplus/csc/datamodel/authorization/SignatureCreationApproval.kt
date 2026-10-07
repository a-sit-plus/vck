package at.asitplus.csc.datamodel.authorization

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.ObjectIdentifierStringSerializer
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.DocumentInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Informed-consent data for signature creation, CSC Data Model 1.0.0 section 10.1. */
@Serializable
data class SignatureCreationApproval(
    /**
     * CSC Data Model 1.0.0 section 10.1: CONDITIONAL
     * Required when [signatureQualifier] is absent; at least one of these identifiers is required.
     */
    @SerialName("credentialID")
    val credentialId: String? = null,
    /**
     * CSC Data Model 1.0.0 section 10.1: CONDITIONAL
     * Required when [credentialId] is absent; at least one of these identifiers is required.
     */
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,
    /**
     * CSC Data Model 1.0.0 section 10.1: REQUIRED
     * Number of signatures covered by this approval.
     */
    @SerialName("numSignatures")
    val numSignatures: Int,
    /**
     * CSC Data Model 1.0.0 section 10.1: REQUIRED
     * Documents and digests covered by this approval.
     */
    @SerialName("documentDigests")
    val documentDigests: List<DocumentInfo>,
    /**
     * CSC Data Model 1.0.0 section 10.1: REQUIRED
     * Algorithm OID used to compute document digests.
     */
    @SerialName("hashAlgorithmOID")
    @Serializable(with = ObjectIdentifierStringSerializer::class)
    val hashAlgorithmOid: ObjectIdentifier,
) {
    init {
        require(credentialId != null || signatureQualifier != null) {
            "credentialID or signatureQualifier must be present"
        }
        require(credentialId == null || credentialId.isNotBlank()) {
            "credentialID must not be blank when present"
        }
        require(numSignatures >= 1) { "numSignatures must be at least 1" }
        require(documentDigests.isNotEmpty()) { "documentDigests must contain at least one document" }
    }
}
