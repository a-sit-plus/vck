package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(val text: String) {

    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    HMAC256("HS256");

    val signatureValueLength
        get() = when (this) {
            ES256 -> 256 / 8
            ES384 -> 384 / 8
            ES512 -> 521 / 8
            HMAC256 -> 256 / 8
        }
}