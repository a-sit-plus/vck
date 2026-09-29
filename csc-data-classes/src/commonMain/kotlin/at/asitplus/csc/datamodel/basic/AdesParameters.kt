package at.asitplus.csc.datamodel.basic

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 7.1. */
@Serializable
data class AdesParameters(
    @SerialName("signature_format")
    val signatureFormat: SignatureFormat? = null,
    @SerialName("conformance_level")
    val conformanceLevel: ConformanceLevel? = null,
    @SerialName("signed_envelope_property")
    val signedEnvelopeProperty: SignedEnvelopeProperty? = null,
    @SerialName("signed_props")
    val signedProps: List<Attribute>? = null,
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
