package at.asitplus.wallet.lib.msg

import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.NullableInstantLongSerializer
import com.benasher44.uuid.uuid4
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * From [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/)
 */
@Serializable
sealed class JsonWebMessage(
    @SerialName("typ")
    val typ: String,
    @SerialName("type")
    val type: String,
    @SerialName("id")
    val id: String,
    @SerialName("from")
    val from: String? = null,
    @SerialName("to")
    val to: Array<String>? = null,
    @SerialName("created_time")
    @kotlinx.serialization.Serializable(with = NullableInstantLongSerializer::class)
    val createdTimestamp: Instant? = null,
    @SerialName("expires_time")
    @kotlinx.serialization.Serializable(with = NullableInstantLongSerializer::class)
    val expiresTimestamp: Instant? = null,
    @SerialName("thid")
    val threadId: String? = null,
    @SerialName("pthid")
    val parentThreadId: String? = null,
    @SerialName("attachments")
    val attachments: Array<JwmAttachment>? = null,
) {

    protected constructor(type: String) : this(
        typ = "application/didcomm-plain+json",
        type = type,
        id = uuid4().toString()
    )

    protected constructor(
        type: String,
        parentThreadId: String? = null,
        threadId: String,
        attachments: Array<JwmAttachment>
    ) : this(
        typ = "application/didcomm-plain+json",
        type = type,
        id = uuid4().toString(),
        parentThreadId = parentThreadId,
        threadId = threadId,
        attachments = attachments,
    )

    protected constructor(
        type: String,
        parentThreadId: String?,
        threadId: String,
    ) : this(
        typ = "application/didcomm-plain+json",
        type = type,
        id = uuid4().toString(),
        parentThreadId = parentThreadId,
        threadId = threadId,
    )

    protected constructor(type: String, threadId: String, attachments: Array<JwmAttachment>) : this(
        typ = "application/didcomm-plain+json",
        type = type,
        id = uuid4().toString(),
        threadId = threadId,
        attachments = attachments,
    )

    open fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<JsonWebMessage>(it)
        }.wrap()
    }
}