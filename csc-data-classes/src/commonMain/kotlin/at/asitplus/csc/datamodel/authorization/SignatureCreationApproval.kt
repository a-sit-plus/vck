package at.asitplus.csc.datamodel.authorization

import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.ObjectIdentifierStringSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Informed-consent data for signature creation, CSC Data Model 1.0.0 section 10.1. */
@Serializable
data class SignatureCreationApproval(
    @SerialName("credentialID")
    val credentialId: String? = null,
    @SerialName("signatureQualifier")
    val signatureQualifier: SignatureQualifier? = null,
    @SerialName("numSignatures")
    val numSignatures: Int,
    @SerialName("documentDigests")
    val documentDigests: List<DocumentInfo>,
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