package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

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
)