package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class AuthnRequestClaims(
    /**
     * OIDC: OPTIONAL. Requests that the listed individual Claims be returned in the ID Token. If present, the listed
     * Claims are being requested to be added to the default Claims in the ID Token. If not present, the default
     * ID Token Claims are requested.
     */
    @SerialName("id_token")
    val idTokenMap: Map<String, AuthnRequestSingleClaim?>? = null,

    /**
     * OIDC: OPTIONAL. Requests that the listed individual Claims be returned from the UserInfo Endpoint. If present,
     * the listed Claims are being requested to be added to any Claims that are being requested using `scope` values.
     * If not present, the Claims being requested from the UserInfo Endpoint are only those requested using `scope`
     * values. When the `userinfo` member is used, the request MUST also use a `response_type` value that results in an
     * Access Token being issued to the Client for use at the UserInfo Endpoint.
     */
    @SerialName("userinfo")
    val userInfoMap: Map<String, AuthnRequestSingleClaim?>? = null,
)