package at.asitplus.wallet.lib.oidvci

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * The OAuth 2.0 Authorization Framework: Error responses,
 * see [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).
 */
@Serializable
data class OAuth2Error(
    /**
     * A single ASCII error code, see [at.asitplus.openid.OpenIdConstants.Errors].
     */
    @SerialName("error")
    val error: String,

    /**
     * OPTIONAL. Human-readable ASCII text providing additional information, used to assist the client developer in
     * understanding the error that occurred. Values for the [errorDescription] parameter MUST NOT include characters
     * outside the set `%x20-21` / `%x23-5B` / `%x5D-7E`.
     */
    @SerialName("error_description")
    val errorDescription: String? = null,

    /**
     * OPTIONAL.  A URI identifying a human-readable web page with information about the error, used to provide the
     * client developer with additional information about the error. Values for the [errorUri] parameter MUST conform
     * to the URI-reference syntax and thus MUST NOT include characters outside the set `%x21` / `%x23-5B` / `%x5D-7E`.
     */
    @SerialName("error_uri")
    val errorUri: String? = null,

    /**
     * REQUIRED if a `state` parameter was present in the client authorization request.
     * The exact value received from the client.
     */
    @SerialName("state")
    val state: String? = null
)