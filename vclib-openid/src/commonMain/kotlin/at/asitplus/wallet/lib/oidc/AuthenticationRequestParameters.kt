package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Some possible parameters for an OIDC Authentication Request.
 *
 * Usually, these parameters are appended to the URL of a [AuthenticationRequest]
 */
@Serializable
data class AuthenticationRequestParameters(
    @SerialName("response_type")
    val responseType: String,
    @SerialName("client_id")
    val clientId: String,
    @SerialName("redirect_uri")
    val redirectUri: String,
    @SerialName("scope")
    val scope: String,
    @SerialName("claims")
    val claims: AuthnRequestClaims? = null,
    @SerialName("state")
    val state: String,
    @SerialName("nonce")
    val nonce: String,
    @SerialName("client_metadata")
    val clientMetadata: RelyingPartyMetadata? = null,
    @SerialName("client_metadata_uri")
    val clientMetadataUri: String? = null,
    @SerialName("id_token_hint")
    val idTokenHint: String? = null,
    @SerialName("request")
    val request: String? = null,
    @SerialName("request_uri")
    val requestUri: String? = null,
    @SerialName("id_token_type")
    val idTokenType: IdTokenType? = null,
    @SerialName("presentation_definition")
    val presentationDefinition: PresentationDefinition? = null,
)
