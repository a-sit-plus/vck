package at.asitplus.wallet.lib.data.rfc7515

import kotlinx.serialization.json.JsonObject

fun interface JsonWebSignatureVerifier {
    suspend operator fun invoke(
        header: JsonObject?,
        signatureInput: ByteArray,
        signature: ByteArray,
    ): Boolean
}