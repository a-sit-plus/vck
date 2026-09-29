@file:OptIn(ExperimentalSerializationApi::class)

package at.asitplus.csc.datamodel.requests

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Flattened union of a full or referenced document, [AdesParameters], and request metadata,
 * as defined by CSC Data Model 1.0.0 section 9.4.
 */
@KeepGeneratedSerializer
@Serializable(with = SignatureRequestSerializer::class)
data class SignatureRequest(
    val document: SignatureRequestContent,
    val adesParameters: AdesParameters = AdesParameters(),
    val signatureQualifier: SignatureQualifier,
    @SerialName("responseURI")
    val responseUri: String? = null,
)
