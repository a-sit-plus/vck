package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class DisplayProperties(
    @SerialName("name")
    val name: String,

    @SerialName("locale")
    val locale: String,
)