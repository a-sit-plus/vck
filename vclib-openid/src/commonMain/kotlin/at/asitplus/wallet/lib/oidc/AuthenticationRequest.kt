package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult.Companion.wrap
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Helper class for allowing serialization of AuthenticationRequestParametersFrom<*>
 */
// TODO: possibly replace this with AuthenticationRequestParametersFrom<*> once it's serializable? or the other way?
@Serializable
data class AuthenticationRequest(
    @Serializable
    val source: AuthenticationRequestSource,
    val parameters: AuthenticationRequestParameters,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    fun toAuthenticationRequestParametersFrom(): AuthenticationRequestParametersFrom<*> {
        return when(source) {
            is AuthenticationRequestSource.Json -> AuthenticationRequestParametersFrom.Json(
                jsonString = source.jsonString,
                parameters = parameters,
            )

            is AuthenticationRequestSource.JwsSigned -> AuthenticationRequestParametersFrom.JwsSigned(
                jwsSigned = source.jwsSigned,
                parameters = parameters,
            )

            is AuthenticationRequestSource.Uri -> AuthenticationRequestParametersFrom.Uri(
                url = source.url,
                parameters = parameters,
            )
        }
    }

    companion object {
        fun deserialize(it: String) = kotlin.runCatching {
            jsonSerializer.decodeFromString<AuthenticationRequest>(it)
        }.wrap()

        fun createInstance(parametersFrom: AuthenticationRequestParametersFrom<*>): AuthenticationRequest {
            return AuthenticationRequest(
                source = when (parametersFrom) {
                    is AuthenticationRequestParametersFrom.JwsSigned -> AuthenticationRequestSource.JwsSigned(
                        jwsSigned = parametersFrom.source
                    )

                    is AuthenticationRequestParametersFrom.Json -> AuthenticationRequestSource.Json(
                        jsonString = parametersFrom.source
                    )

                    is AuthenticationRequestParametersFrom.Uri -> AuthenticationRequestSource.Uri(
                        url = parametersFrom.source
                    )
                },
                parameters = parametersFrom.parameters
            )
        }
    }
}