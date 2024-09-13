package at.asitplus.dif.rqes.Enums

import kotlinx.serialization.SerialName

/**
 * All available signed envelope properties and their associated [SignatureFormat]s
 */
enum class SignedEnvelopeProperty(val viableSignatureFormats: List<SignatureFormat>) {

    @SerialName("Detached")
    DETACHED(listOf(SignatureFormat.CADES, SignatureFormat.JADES, SignatureFormat.XADES)),

    @SerialName("Attached")
    ATTACHED(listOf(SignatureFormat.CADES, SignatureFormat.JADES)),

    @SerialName("Parallel")
    PARALLEL(listOf(SignatureFormat.CADES, SignatureFormat.JADES)),

    @SerialName("Certification")
    CERTIFICATION(listOf(SignatureFormat.PADES)),

    @SerialName("Revision")
    REVISION(listOf(SignatureFormat.PADES)),

    @SerialName("Enveloped")
    ENVELOPED(listOf(SignatureFormat.XADES)),

    @SerialName("Enveloping")
    ENVELOPING(listOf(SignatureFormat.XADES));

    companion object {
        fun defaultProperty(signatureFormat: SignatureFormat) =
            when (signatureFormat) {
                SignatureFormat.CADES, SignatureFormat.JADES -> ATTACHED
                SignatureFormat.XADES -> CERTIFICATION
                SignatureFormat.PADES -> ENVELOPED
            }
    }
}