package at.asitplus.wallet.lib.msg

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.aries.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject

/**
 *
 */
@Serializable
data class JwmAttachmentData(
    @SerialName("json")
    val json: JsonObject? = null,
    @SerialName("jws")
    val jws: String? = null,
    @SerialName("base64")
    val base64: String? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JwmAttachmentData>(it)
        }.wrap()
    }
}