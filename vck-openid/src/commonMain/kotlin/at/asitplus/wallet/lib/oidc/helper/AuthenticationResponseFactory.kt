package at.asitplus.wallet.lib.oidc.helper

import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParametersFrom
import at.asitplus.wallet.lib.oidc.AuthenticationResponse
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlin.random.Random

internal class AuthenticationResponseFactory(
    val jwsService: JwsService,
) {
    internal suspend fun createAuthenticationResponse(
        request: AuthenticationRequestParametersFrom,
        response: AuthenticationResponse,
    ) = when (request.parameters.responseMode) {
        DirectPost -> authnResponseDirectPost(request, response)
        DirectPostJwt -> authnResponseDirectPostJwt(request, response)
        Query -> authnResponseQuery(request, response)
        Fragment, null -> authnResponseFragment(request, response)
        is Other -> TODO()
    }

    /**
     * Per OID4VP, the response may either be signed, or encrypted (never signed and encrypted!)
     */
    internal suspend fun authnResponseDirectPostJwt(
        request: AuthenticationRequestParametersFrom,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrl
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        val responseSerialized = buildJarm(request, response)
        val jarm = AuthenticationResponseParameters(
            response = responseSerialized,
            state = request.parameters.state
        )
        return AuthenticationResponseResult.Post(url, jarm.encodeToParameters())
    }

    internal fun authnResponseDirectPost(
        request: AuthenticationRequestParametersFrom,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrl
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        return AuthenticationResponseResult.Post(url, response.params.encodeToParameters())
    }

    internal fun authnResponseQuery(
        request: AuthenticationRequestParametersFrom,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Redirect {
        val url = request.parameters.redirectUrl?.let { redirectUrl ->
            URLBuilder(redirectUrl).apply {
                response.params.encodeToParameters().forEach {
                    this.parameters.append(it.key, it.value)
                }
            }.buildString()
        } ?: throw OAuth2Exception(Errors.INVALID_REQUEST)

        return AuthenticationResponseResult.Redirect(url, response.params)
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    internal fun authnResponseFragment(
        request: AuthenticationRequestParametersFrom,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Redirect {
        val url = request.parameters.redirectUrl?.let { redirectUrl ->
            URLBuilder(redirectUrl).apply {
                encodedFragment = response.params.encodeToParameters().formUrlEncode()
            }.buildString()
        } ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        return AuthenticationResponseResult.Redirect(url, response.params)
    }


    private suspend fun buildJarm(
        request: AuthenticationRequestParametersFrom,
        response: AuthenticationResponse,
    ) =
        if (response.clientMetadata != null && response.jsonWebKeys != null && response.clientMetadata.requestsEncryption()) {
            val alg = response.clientMetadata.authorizationEncryptedResponseAlg!!
            val enc = response.clientMetadata.authorizationEncryptedResponseEncoding!!
            val jwk = response.jsonWebKeys.first()
            val nonce =
                runCatching { request.parameters.nonce?.decodeToByteArray(Base64()) }.getOrNull()
                    ?: runCatching { request.parameters.nonce?.encodeToByteArray() }.getOrNull()
                    ?: Random.Default.nextBytes(16)
            jwsService.encryptJweObject(
                header = JweHeader(
                    algorithm = alg,
                    encryption = enc,
                    type = null,
                    agreementPartyVInfo = nonce.encodeToByteArray(Base64()),
                    agreementPartyUInfo = Random.nextBytes(16),
                    keyId = jwk.keyId,
                ),
                payload = response.params,
                serializer = AuthenticationResponseParameters.serializer(),
                recipientKey = jwk,
                jweAlgorithm = alg,
                jweEncryption = enc,
            ).map { it.serialize() }.getOrElse {
                Napier.w("buildJarm error", it)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        } else {
            jwsService.createSignedJwsAddingParams(
                payload = response.params,
                serializer = AuthenticationResponseParameters.serializer(),
                addX5c = false
            ).map { it.serialize() }.getOrElse {
                Napier.w("buildJarm error", it)
                throw OAuth2Exception(Errors.INVALID_REQUEST)
            }
        }

    private fun RelyingPartyMetadata.requestsEncryption() =
        authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null
}