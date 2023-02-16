package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = JweAlgorithmSerializer::class)
enum class JweAlgorithm(val text: String) {

    ECDH_ES("ECDH-ES");

}