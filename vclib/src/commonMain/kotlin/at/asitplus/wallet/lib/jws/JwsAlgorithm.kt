package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = JwsAlgorithmSerializer::class)
enum class JwsAlgorithm(val text: String) {

    ES256("ES256");

    val signatureValueLength
        get() = when (this) {
            ES256 -> 32
        }
}