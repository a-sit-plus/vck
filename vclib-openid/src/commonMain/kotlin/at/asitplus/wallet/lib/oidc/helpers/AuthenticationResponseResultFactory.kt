package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import at.asitplus.crypto.datatypes.jws.JweEncryption
import at.asitplus.crypto.datatypes.jws.JweHeader
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestSource
import at.asitplus.wallet.lib.oidc.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.RelyingPartyMetadata
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.URLBuilder
import kotlin.random.Random


class AuthenticationResponseResultFactory(
    val jwsService: JwsService,
) {
    suspend fun createAuthenticationResponseResult(
        responsePreparationState: AuthenticationResponsePreparationState,
        responseParameters: AuthenticationResponseParameters,
    ): KmmResult<AuthenticationResponseResult> {
        return when (responsePreparationState.responseModeParameters) {
            is ResponseModeParameters.DirectPost -> KmmResult.success(
                AuthenticationResponseResult.Post(
                    url = responsePreparationState.responseModeParameters.responseUrl,
                    params = responseParameters.encodeToParameters(),
                )
            )

            is ResponseModeParameters.DirectPostJwt -> KmmResult.runCatching {
                authnResponseDirectPostJwt(
                    requestSource = responsePreparationState.request.source,
                    responseModeParameters = responsePreparationState.responseModeParameters,
                    clientMetadata = responsePreparationState.clientMetadata,
                    clientJsonWebKeySet = responsePreparationState.clientJsonWebKeySet,
                    responseParameters = responseParameters,
                )
            }.wrap()

            is ResponseModeParameters.Query -> KmmResult.runCatching {
                authnResponseQuery(
                    responseModeParameters = responsePreparationState.responseModeParameters,
                    responseParameters = responseParameters,
                )
            }.wrap()

            is ResponseModeParameters.Fragment -> KmmResult.runCatching {
                authnResponseFragment(
                    responseModeParameters = responsePreparationState.responseModeParameters,
                    responseParameters = responseParameters,
                )
            }.wrap()
        }
    }

    private suspend fun authnResponseDirectPostJwt(
        requestSource: AuthenticationRequestSource,
        responseModeParameters: ResponseModeParameters.DirectPostJwt,
        clientMetadata: RelyingPartyMetadata,
        clientJsonWebKeySet: JsonWebKeySet?,
        responseParameters: AuthenticationResponseParameters,
    ): AuthenticationResponseResult.Post {
        val certKey =
            (requestSource as? AuthenticationRequestSource.JwsSigned)?.jwsSigned?.header?.certificateChain?.firstOrNull()?.publicKey?.toJsonWebKey()
        val clientJsonWebKeys = clientJsonWebKeySet?.keys.combine(certKey)

        val responseSerialized = buildJarm(
            clientMetadata = clientMetadata,
            clientJsonWebKeys = clientJsonWebKeys,
            responseParameters = responseParameters,
        )
        val jarm = AuthenticationResponseParameters(response = responseSerialized)
        return AuthenticationResponseResult.Post(
            url = responseModeParameters.responseUrl,
            params = jarm.encodeToParameters(),
        )
    }

    private fun authnResponseQuery(
        responseModeParameters: ResponseModeParameters.Query,
        responseParameters: AuthenticationResponseParameters,
    ): AuthenticationResponseResult.Redirect {
        val url = URLBuilder(responseModeParameters.redirectUrl).apply {
            responseParameters.encodeToParameters().forEach {
                this.parameters.append(it.key, it.value)
            }
        }.buildString()

        return AuthenticationResponseResult.Redirect(
            url = url,
            params = responseParameters,
        )
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    private fun authnResponseFragment(
        responseModeParameters: ResponseModeParameters.Fragment,
        responseParameters: AuthenticationResponseParameters,
    ): AuthenticationResponseResult.Redirect {
        val url = URLBuilder(responseModeParameters.redirectUrl).apply {
            encodedFragment = responseParameters.encodeToParameters().formUrlEncode()
        }.buildString()
        return AuthenticationResponseResult.Redirect(url, responseParameters)
    }


    private suspend fun buildJarm(
        clientMetadata: RelyingPartyMetadata,
        clientJsonWebKeys: Collection<JsonWebKey>,
        responseParameters: AuthenticationResponseParameters,
    ): String {
        val responseEncryptionParameters = clientMetadata.responseEncryptionParameters()

        return if (responseEncryptionParameters != null) {
            val alg = responseEncryptionParameters.algoritm
            val enc = responseEncryptionParameters.encoding
            val jwk = clientJsonWebKeys.first()
            jwsService.encryptJweObject(
                header = JweHeader(
                    algorithm = alg,
                    encryption = enc,
                    type = null,
                    agreementPartyVInfo = Random.nextBytes(16), // TODO nonce from authn request
                    keyId = jwk.keyId,
                ),
                payload = responseParameters.serialize().encodeToByteArray(),
                recipientKey = jwk,
                jweAlgorithm = alg,
                jweEncryption = enc,
            ).map { it.serialize() }.getOrElse {
                Napier.w("buildJarm error", it)
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }
        } else {
            jwsService.createSignedJwsAddingParams(
                payload = responseParameters.serialize().encodeToByteArray(), addX5c = false
            ).map { it.serialize() }.getOrElse {
                Napier.w("buildJarm error", it)
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            }
        }
    }

    private fun Collection<JsonWebKey>?.combine(certKey: JsonWebKey?): Collection<JsonWebKey> {
        return certKey?.let { (this ?: listOf()) + certKey } ?: this ?: listOf()
    }
}

private fun RelyingPartyMetadata.responseEncryptionParameters(): ResponseEncryptionParameters? {
    return kotlin.runCatching {
        ResponseEncryptionParameters(
            algoritm = authorizationEncryptedResponseAlg!!,
            encoding = authorizationEncryptedResponseEncoding!!,
        )
    }.getOrElse {
        null
    }
}

private data class ResponseEncryptionParameters(
    val algoritm: JweAlgorithm,
    val encoding: JweEncryption,
)