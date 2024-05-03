package at.asitplus.wallet.lib.iso

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.data.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * JWS representation of a [MobileDrivingLicence].
 */
@Serializable
data class MobileDrivingLicenceJwsNamespace(
    @SerialName("org.iso.18013.5.1")
    val mdl: MobileDrivingLicence,
) {

    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<MobileDrivingLicenceJwsNamespace>(it)
        }.wrap()
    }

}