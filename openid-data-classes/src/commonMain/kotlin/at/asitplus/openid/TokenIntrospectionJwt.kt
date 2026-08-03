package at.asitplus.openid

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.JwsCompactStringSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.data.MediaTypes.Application
import at.asitplus.wallet.lib.data.MediaTypes.Application.INTROSPECTION_JWT
import at.asitplus.wallet.lib.data.MediaTypes.Application.JSON
import kotlinx.serialization.KSerializer
import kotlin.jvm.JvmInline

/**
 * [RFC 9701: JWT Response for OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/rfc9701/):
 * Response when request HTTP HEADER Accept = [Application.INTROSPECTION_JWT];
 * Payload defined in [TokenIntrospectionResponseJwtPayload]
 *
 * CONTAINS [Serializer] BUT NOT MARKED SERIALIZABLE. SEE [JwsCompactStringSerializer]
 *
 * For [Application.JSON] use [TokenIntrospectionResponseJson] as defined in
 * [RFC 7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
 */
@JvmInline
value class TokenIntrospectionResponseJwt(
    val value: JwsCompactTyped<TokenIntrospectionResponseJwtPayload>
) : TokenIntrospectionResponse {

    override fun toString(): String = value.toString()

    //Only necessary because we cannot tag the class as @Serializable
    object Serializer :
        KSerializer<TokenIntrospectionResponseJwt> by
        TransformingSerializerTemplate<TokenIntrospectionResponseJwt, JwsCompactTyped<TokenIntrospectionResponseJwtPayload>>(
            InternalTypedSerializer,
            encodeAs = { it.value },
            decodeAs = ::TokenIntrospectionResponseJwt,
        )

    private object InternalTypedSerializer :
        KSerializer<JwsCompactTyped<TokenIntrospectionResponseJwtPayload>> by JwsTypedSerializerTemplate(
            JwsCompactStringSerializer,
            TokenIntrospectionResponseJwtPayload.serializer(),
        )
}
