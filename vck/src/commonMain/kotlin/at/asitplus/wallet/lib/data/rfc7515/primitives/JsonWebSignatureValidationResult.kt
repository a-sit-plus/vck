package at.asitplus.wallet.lib.data.rfc7515.primitives

data class JsonWebSignatureValidationResult(
    val jsonWebSignature: JsonWebSignature,
    val signatureValidities: List<Boolean>,
) {
    val isValid: Boolean?
        get() = if (signatureValidities.all { it }) true
        else if (!signatureValidities.any { it }) false
        else null
}