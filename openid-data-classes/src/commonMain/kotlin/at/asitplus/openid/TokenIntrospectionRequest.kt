package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662): Request.
 */
@Serializable
data class TokenIntrospectionRequest(
    /**
     * REQUIRED.  The string value of the token.  For access tokens, this
     * is the `access_token` (see [TokenResponseParameters.accessToken]) value returned from the token endpoint
     * defined in OAuth 2.0 (RFC6749), Section 5.1.  For refresh tokens,
     * this is the `refresh_token` (see [TokenResponseParameters.refreshToken]) value returned from the token endpoint
     * as defined in OAuth 2.0 (RFC6749), Section 5.1.  Other token types
     * are outside the scope of this specification.
     */
    @SerialName("token")
    val token: String,

    /**
     * OPTIONAL.  A hint about the type of the token submitted for
     * introspection.  The protected resource MAY pass this parameter to
     * help the authorization server optimize the token lookup.  If the
     * server is unable to locate the token using the given hint, it MUST
     * extend its search across all of its supported token types.  An
     * authorization server MAY ignore this parameter, particularly if it
     * is able to detect the token type automatically.  Values for this
     * field are defined in the "OAuth Token Type Hints" registry defined
     * in OAuth Token Revocation (RFC7009).
     */
    @SerialName("token_type_hint")
    val tokenTypeHint: String? = null,
)
