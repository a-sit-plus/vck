package at.asitplus.wallet.lib.jws

import kotlinx.serialization.Serializable

@Serializable(with = JwkTypeSerializer::class)
enum class JwkType(val text: String) {

    EC("EC"),
    RSA("RSA");

}