package at.asitplus.openid

import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.data.MediaTypes.Application
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlin.time.Instant

/**
 * [RFC 9701: JWT Response for OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/rfc9701/):
 * Response Payload when request HTTP HEADER Accept = [Application.INTROSPECTION_JWT];
 * Subsequently to be used inside a JWT. Uses [TokenIntrospectionResponseJson] internally.
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
    /** MUST be set to the time when the introspection response was created by the authorization server */
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val iat: Instant,
    /** A JSON object containing the members of the token introspection response, as specified in [RFC7662](https://datatracker.ietf.org/doc/html/rfc7662) */
    @SerialName("token_introspection")
    val tokenIntrospection: TokenIntrospectionResponseJson,
)