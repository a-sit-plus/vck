package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.SignatureRequestContent
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/**
 * CSC Data Model Bindings 1.0.0 section 6.2.1 / ETSI TS 119 432 Annex A.6.4: REQUIRED
 * Flattened QES signature request.
 */
@KeepGeneratedSerializer
@Serializable(with = QesSignatureRequestSerializer::class)
data class QesSignatureRequest(
    /**
     * CSC Data Model 1.0.0 sections 8.1 and 8.3: REQUIRED
     * Document data or reference to be signed.
     */
    val document: SignatureRequestContent,
    /**
     * CSC Data Model 1.0.0 section 7.1: REQUIRED
     * AdES parameters; individual parameters are optional as specified.
     */
    val adesParameters: AdesParameters = AdesParameters(),
    /**
     * ETSI TS 119 432 Annex A.6.4: OPTIONAL
     * Signing algorithm for this document.
     */
    val signingAlgorithm: SigningAlgorithm? = null,
    /**
     * CSC Data Model Bindings 1.0.0 section 6.2.1: OPTIONAL
     * Callback URI for the signature result.
     */
    @SerialName("responseURI")
    val responseUri: String? = null,
    /**
     * ETSI TS 119 432 Annex A.6.4: OPTIONAL
     * Structured checksum. CSC Data Model Bindings 1.0.0 normatively specifies an SRI string for this field; VC-K
     * follows ETSI TS 119 432 where the definitions conflict and uses the structured [Hash] form throughout.
     */
    val checksum: Hash? = null,
    /**
     * ETSI TS 119 432 Annex A.6.4: REQUIRED for each signature request.
     * The enclosing QES transaction may also carry its CSC-level qualifier.
     */
    val signatureQualifier: SignatureQualifier,
)
