package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.data.jsonSerializer
import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.base64.encodeBase64
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.content.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
@Serializable
data class JwmAttachment(
    @SerialName("id")
    val id: String,
    @SerialName("media_type")
    val mediaType: String? = null,
    @SerialName("data")
    val data: JwmAttachmentData,
    @SerialName("filename")
    val filename: String? = null,
    @SerialName("parent")
    val parent: String? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    fun decodeString(): String? {
        if (data.base64 != null)
            return data.base64.decodeBase64ToArray()?.decodeToString()
        if (data.jws != null)
            return data.jws
        return null
            .also { Napier.w("Could not decode JWM attachment") }
    }

    fun decodeBinary(): ByteArray? {
        if (data.base64 != null)
            return data.base64.decodeBase64ToArray()
        return null
            .also { Napier.w("Could not binary decode JWM attachment") }
    }

    companion object {

        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JwmAttachment>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }

        fun encodeBase64(data: String) = JwmAttachment(
            id = uuid4().toString(),
            mediaType = "application/base64",
            data = JwmAttachmentData(
                base64 = data.encodeToByteArray().encodeBase64()
            )
        )

        fun encode(data: ByteArray, filename: String, mediaType: String, parent: String) = JwmAttachment(
            id = uuid4().toString(),
            mediaType = mediaType,
            filename = filename,
            parent = parent,
            data = JwmAttachmentData(
                base64 = data.encodeBase64()
            )
        )

        fun encodeJws(data: String) = JwmAttachment(
            id = uuid4().toString(),
            mediaType = "application/jws",
            data = JwmAttachmentData(
                jws = data
            )
        )
    }
}