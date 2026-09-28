package at.asitplus.csc.datamodel.requests

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.SignatureCreationRequestContent


/**
 * Flattened union of a document, [AdesParameters], and [SigningAlgorithm], as defined by
 * CSC Data Model 1.0.0 section 9.3.
 */

data class SignatureCreationRequest(
    val document: SignatureCreationRequestContent,
    val adesParameters: AdesParameters = AdesParameters(),
    val signingAlgorithm: SigningAlgorithm,
)