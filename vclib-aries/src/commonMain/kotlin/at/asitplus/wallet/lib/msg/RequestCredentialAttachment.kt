package at.asitplus.wallet.lib.msg

import at.asitplus.wallet.lib.aries.jsonSerializer
import at.asitplus.wallet.lib.data.dif.CredentialManifest
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString


/**
 * From [ARIES RFC 0511](https://github.com/hyperledger/aries-rfcs/blob/main/features/0511-dif-cred-manifest-attach)
 */
@Serializable
data class RequestCredentialAttachment(
    @SerialName("credential-manifest")
    val credentialManifest: CredentialManifest,
    @SerialName("presentation-submission")
    val presentationSubmission: PresentationSubmission? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<RequestCredentialAttachment>(it)
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }
}