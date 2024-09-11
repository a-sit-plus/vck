package at.asitplus.dif.rqes.Enums


/**
 * TODO: Presumably needs a custom serializer. First try enum class without @Serializable notation but lets see
 */
enum class SignedEnvelopeProperty(val viableSignatureFormats: List<SignatureFormat>) {
    DETACHED(listOf(SignatureFormat.CADES, SignatureFormat.JADES, SignatureFormat.XADES)),
    ATTACHED(listOf(SignatureFormat.CADES, SignatureFormat.JADES)),
    PARALLEL(listOf(SignatureFormat.CADES, SignatureFormat.JADES)),
    CERTIFICATION(listOf(SignatureFormat.PADES)),
    REVISION(listOf(SignatureFormat.PADES)),
    ENVELOPED(listOf(SignatureFormat.XADES)),
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