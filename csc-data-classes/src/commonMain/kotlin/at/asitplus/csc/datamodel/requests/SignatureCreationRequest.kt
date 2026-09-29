@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.csc.datamodel.requests

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.SignatureCreationRequestContent
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.Serializable

/**
 * Flattened union of a document, [AdesParameters], and [SigningAlgorithm], as defined by
 * CSC Data Model 1.0.0 section 9.3.
 */
@KeepGeneratedSerializer
@Serializable(with = SignatureCreationRequestSerializer::class)
data class SignatureCreationRequest(
    val document: SignatureCreationRequestContent,
    val adesParameters: AdesParameters = AdesParameters(),
    val signingAlgorithm: SigningAlgorithm,
)
