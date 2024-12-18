package at.asitplus.rqes.collection_entries

import kotlinx.serialization.SerialName

data class CscKeyParameters(
    @SerialName("status")
    val status: KeyStatusOptions,

    @SerialName("algo")
    val algo: Collection<String>,

    @SerialName("len")
    val len: UInt,

    @SerialName("curve")
    val curve: String? = null,
) {
    enum class KeyStatusOptions {
        @SerialName("enabled")
        ENABLED,

        @SerialName("disabled")
        DISABLED
    }
}