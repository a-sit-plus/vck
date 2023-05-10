package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import io.github.aakira.napier.Napier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

/**
 * Some possible parameters for an OIDC Authentication Response.
 *
 * Usually, these parameters are appended to the URL of an [AuthenticationResponse].
 */
@Serializable
data class AuthenticationResponseParameters(
    /**
     * Signed [IdToken] structure
     */
    @SerialName("id_token")
    val idToken: String,
    @SerialName("vp_token")
    val vpToken: String? = null,
    @SerialName("presentation_submission")
    val presentationSubmission: PresentationSubmission? = null,
    @SerialName("state")
    val state: String,
) {

    fun serialize() = jsonSerializer.encodeToJsonElement(this) as JsonObject

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AuthenticationResponseParameters

        if (idToken != other.idToken) return false
        if (vpToken != other.vpToken) return false
        if (presentationSubmission != other.presentationSubmission) return false
        if (state != other.state) return false

        return true
    }

    override fun hashCode(): Int {
        var result = idToken.hashCode()
        result = 31 * result + (vpToken?.hashCode() ?: 0)
        result = 31 * result + (presentationSubmission?.hashCode() ?: 0)
        result = 31 * result + state.hashCode()
        return result
    }

    companion object {
        fun deserialize(it: Map<String, String>) = kotlin.runCatching {
            jsonSerializer.decodeFromJsonElement<AuthenticationResponseParameters>(buildJsonObject {
                it.forEach { (k, v) -> put(k, jsonSerializer.decodeFromString(v)) }
            })
        }.getOrElse {
            Napier.w("deserialize failed", it)
            null
        }
    }

}
