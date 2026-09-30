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
    /** CSC Data Model 1.0.0 section 9.3: REQUIRED
     * One document content, reference, or representation.
     */
    val document: SignatureCreationRequestContent,
    /** CSC Data Model 1.0.0 section 9.3: REQUIRED
     * AdES signature format and document properties.
     */
    val adesParameters: AdesParameters = AdesParameters(),
    /** CSC Data Model 1.0.0 section 9.3: REQUIRED
     * Algorithm used to create the signature.
     */
    val signingAlgorithm: SigningAlgorithm,
)
