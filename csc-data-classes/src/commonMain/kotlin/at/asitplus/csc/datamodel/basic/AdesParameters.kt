package at.asitplus.csc.datamodel.basic

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 7.1. */
@Serializable
data class AdesParameters(
    /** CSC Data Model 1.0.0 section 7.1: Requested signature format. */
    @SerialName("signature_format")
    val signatureFormat: SignatureFormat? = null,
    /** CSC Data Model 1.0.0 section 7.1: Required AdES conformance level. */
    @SerialName("conformance_level")
    val conformanceLevel: ConformanceLevel? = null,
    /** CSC Data Model 1.0.0 section 7.1: Whether the signature is enveloped or detached. */
    @SerialName("signed_envelope_property")
    val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
    /** CSC Data Model 1.0.0 section 7.1: Signed document properties to include. */
    @SerialName("signed_props")
    val signedProps: List<Attribute>? = null,
    /** CSC Data Model 1.0.0 section 7.1: Optional reference URI for the signature. */
    @SerialName("referenceUri")
    val referenceUri: String? = null,
) {
    init {
        require(
            signatureFormat == null ||
                    signedEnvelopeProperty == null ||
                    signatureFormat in signedEnvelopeProperty.viableSignatureFormats
        ) {
            "$signedEnvelopeProperty is not valid for $signatureFormat"
        }
    }
}
