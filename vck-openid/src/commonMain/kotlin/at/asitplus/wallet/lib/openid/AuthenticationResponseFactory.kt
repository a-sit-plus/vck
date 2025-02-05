package at.asitplus.wallet.lib.openid

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToByteArray
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encodeToString
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

internal class AuthenticationResponseFactory(
    val jwsService: JwsService,
) {
    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun createAuthenticationResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = when (request.parameters.responseMode) {
        DirectPost -> authnResponseDirectPost(request, response)
        DirectPostJwt -> authnResponseDirectPostJwt(request, response)
        Query -> authnResponseQuery(request, response)
        Fragment, null -> authnResponseFragment(request, response)
        is Other -> TODO()
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun authnResponseDirectPostJwt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrlExtracted
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        val responseSerialized = buildJarm(request, response)
        val jarm = AuthenticationResponseParameters(
            response = responseSerialized,
            state = request.parameters.state
        )
        return AuthenticationResponseResult.Post(url, jarm.encodeToParameters())
    }

    @Throws(OAuth2Exception::class)
    internal fun authnResponseDirectPost(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrlExtracted
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        return AuthenticationResponseResult.Post(url, response.params.encodeToParameters())
    }

    @Throws(OAuth2Exception::class)
    internal fun authnResponseQuery(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Redirect {
        val url = request.parameters.redirectUrlExtracted?.let { redirectUrl ->
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
    @Throws(OAuth2Exception::class)
    internal fun authnResponseFragment(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Redirect {
        val url = request.parameters.redirectUrlExtracted?.let { redirectUrl ->
            URLBuilder(redirectUrl).apply {
                encodedFragment = response.params.encodeToParameters().formUrlEncode()
            }.buildString()
        } ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        return AuthenticationResponseResult.Redirect(url, response.params)
    }

    /**
     * Per OID4VP, the response may either be signed, or encrypted, or even signed and encrypted
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun buildJarm(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = if (response.requestsEncryption()) {
        encrypt(request, response)
    } else if (response.requestsSignature()) {
        sign(response.params)
    } else {
        odcJsonSerializer.encodeToString(response)
    }

    private suspend fun sign(payload: AuthenticationResponseParameters): String =
        jwsService.createSignedJwsAddingParams(
            payload = payload,
            serializer = AuthenticationResponseParameters.serializer(),
            addX5c = false
        ).map { it.serialize() }.getOrElse {
            Napier.w("buildJarm error", it)
            throw OAuth2Exception(Errors.INVALID_REQUEST, it)
        }

    private suspend fun encrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): String {
        val algorithm = response.clientMetadata!!.authorizationEncryptedResponseAlg!!
        val encryption = response.clientMetadata.authorizationEncryptedResponseEncoding!!
        val recipientKey = response.jsonWebKeys!!.getEcdhEsKey()
        val recipientNonce = runCatching { request.parameters.nonce?.decodeToByteArray(Base64()) }.getOrNull()
            ?: runCatching { request.parameters.nonce?.encodeToByteArray() }.getOrNull()
            ?: Random.nextBytes(16)
        // TODO Verify whether its always base64-url-no-padding, as in iso/iec 18013-7:2024
        val apv = recipientNonce.encodeToByteArray(Base64UrlStrict)
        val senderNonce = response.mdocGeneratedNonce?.encodeToByteArray()
            ?: Random.nextBytes(16)
        val apu = senderNonce.encodeToByteArray(Base64UrlStrict)
        val header = JweHeader(
            algorithm = algorithm,
            encryption = encryption,
            type = null, // TODO type?
            agreementPartyVInfo = apv,
            agreementPartyUInfo = apu,
            keyId = recipientKey.keyId,
        )
        val jwe = if (response.requestsSignature()) {
            jwsService.encryptJweObject(
                header = header,
                payload = sign(response.params),
                serializer = String.serializer(),
                recipientKey = recipientKey,
                jweAlgorithm = algorithm,
                jweEncryption = encryption,
            )
        } else {
            jwsService.encryptJweObject(
                header = header,
                payload = response.params,
                serializer = AuthenticationResponseParameters.serializer(),
                recipientKey = recipientKey,
                jweAlgorithm = algorithm,
                jweEncryption = encryption,
            )
        }
        return jwe.map { it.serialize() }.getOrElse {
            Napier.w("buildJarm error", it)
            throw OAuth2Exception(Errors.INVALID_REQUEST, it)
        }
    }


    @Throws(OAuth2Exception::class)
    private fun Collection<JsonWebKey>.getEcdhEsKey(): JsonWebKey =
        filter { it.type == JwkType.EC }.let { ecKeys ->
            ecKeys.firstOrNull { it.publicKeyUse == "enc" }
                ?: ecKeys.firstOrNull { it.algorithm == JweAlgorithm.ECDH_ES }
                ?: ecKeys.firstOrNull()
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "no suitable ECDH ES key in $ecKeys")
        }

}

internal fun AuthenticationResponse.requestsEncryption(): Boolean =
    clientMetadata != null && jsonWebKeys != null && clientMetadata.requestsEncryption()

internal fun AuthenticationResponse.requestsSignature(): Boolean =
    clientMetadata != null && clientMetadata.authorizationSignedResponseAlg != null

internal fun RelyingPartyMetadata.requestsEncryption() =
    authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null