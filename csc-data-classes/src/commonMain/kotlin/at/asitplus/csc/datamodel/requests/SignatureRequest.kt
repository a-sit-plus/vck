package at.asitplus.csc.datamodel.requests

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import at.asitplus.csc.datamodel.serializers.SignatureRequestSerializer
import kotlinx.serialization.Serializable


/**
 * Flattened union of a full or referenced document, [AdesParameters], and request metadata,
 * as defined by CSC Data Model 1.0.0 section 9.4.
 */
data class SignatureRequest(
    val document: SignatureRequestContent,
    val adesParameters: AdesParameters = AdesParameters(),
    val signatureQualifier: SignatureQualifier,
    val responseUri: String? = null,
)
