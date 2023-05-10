package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString

/**
 * [Attachment format](https://github.com/hyperledger/aries-rfcs/tree/main/features/0510-dif-pres-exch-attach)
 * for [at.asitplus.wallet.lib.agent.PresentProofProtocol]
 */
@Serializable
data class RequestPresentationAttachment(
    @SerialName("presentation_definition")
    val presentationDefinition: PresentationDefinition,
    @SerialName("options")
    val options: RequestPresentationAttachmentOptions,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<RequestPresentationAttachment>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}