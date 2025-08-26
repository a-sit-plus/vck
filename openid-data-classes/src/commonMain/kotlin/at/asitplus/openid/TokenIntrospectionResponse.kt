package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662): Response.
 */
@Serializable
data class TokenIntrospectionResponse(
    /**
     * REQUIRED.  Boolean indicator of whether or not the presented token
     * is currently active.  The specifics of a token's "active" state
     * will vary depending on the implementation of the authorization
     * server and the information it keeps about its tokens, but a "true"
     * value return for the "active" property will generally indicate
     * that a given token has been issued by this authorization server,
     * has not been revoked by the resource owner, and is within its
     * given time window of validity (e.g., after its issuance time and
     * before its expiration time).
     */
    @SerialName("active")
    val active: Boolean,

    /**
     * OPTIONAL.A JSON string containing a space-separated list of
     * scopes associated with this token, in the format described in
     * Section 3.3 of OAuth 2.0 [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
     */
    @SerialName("client_id")
    val clientId: String? = null,

    /**
     * OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
     */
    @SerialName("username")
    val username: String? = null,

    /**
     * OPTIONAL.  Type of the token as defined in Section 5.1 of OAuth 2.0
     * [RFC6749](https://datatracker.ietf.org/doc/html/rfc6749).
     */
    @SerialName("token_type")
    val tokenType: String? = null,

    /**
     * OPTIONAL.Integer timestamp, measured in the number of seconds
     * since January 1 1970 UTC, indicating when this token will expire,
     * as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of seconds
     * since January 1 1970 UTC, indicating when this token was
     * originally issued, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    /**
     * OPTIONAL.  Integer timestamp, measured in the number of seconds
     * since January 1 1970 UTC, indicating when this token is not to be
     * used before, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("nbf")
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * OPTIONAL.  Subject of the token, as defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     * Usually a machine-readable identifier of the resource owner who
     * authorized this token.
     */
    @SerialName("sub")
    val subject: String? = null,

    /**
     * OPTIONAL.  Service-specific string identifier or list of string
     * identifiers representing the intended audience for this token, as
     * defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("aud")
    val audience: String? = null,

    /**
     * OPTIONAL.  String representing the issuer of this token, as
     * defined in JWT [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("iss")
    val issuer: String? = null,

    /**
     * OPTIONAL.  String identifier for the token, as defined in JWT
     * [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519).
     */
    @SerialName("jti")
    val jwtId: String? = null,

    @SerialName("authorization_details")
    val authorizationDetails: Set<AuthorizationDetails>? = null,

    )
