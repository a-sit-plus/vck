package at.asitplus.openid

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.wallet.lib.data.MediaTypes.Application
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * [RFC 9701: JWT Response for OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/rfc9701/):
 * Response to HTTP HEADER Accept = [Application.INTROSPECTION_JWT]; subsequently to be used inside a JWT.
 * Uses [TokenIntrospectionResponseJson] internally.
 *
 * For [Application.JSON] use [TokenIntrospectionResponseJson] as defined in
 * [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
 */
@Serializable
data class TokenIntrospectionResponseJwtPayload(
    /** MUST be set to the issuer URL of the authorization server */
    @SerialName("iss")
    val issuer: String,
    /** MUST identify the resource server receiving the token introspection response.*/
    @SerialName("aud")
    val audience: String,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val iat: Instant,
    @SerialName("token_introspection")
    val tokenIntrospection: TokenIntrospectionResponseJson,
) {}