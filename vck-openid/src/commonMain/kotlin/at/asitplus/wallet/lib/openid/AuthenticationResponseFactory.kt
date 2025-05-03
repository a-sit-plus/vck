package at.asitplus.wallet.lib.openid

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

internal class AuthenticationResponseFactory(
    val signJarm: SignJwtFun<AuthenticationResponseParameters>,
    val encryptJarm: EncryptJweFun,
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
        DcApi -> TODO()
        is Other -> TODO()
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun authnResponseDirectPostJwt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrlExtracted
            ?: throw InvalidRequest("no response_uri or redirect_uri")
        val responseSerialized = buildJarm(request, response)
        val jarm = AuthenticationResponseParameters(
            response = responseSerialized,
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
            ?: throw InvalidRequest("no response_uri or redirect_uri")
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
        } ?: throw InvalidRequest("no redirect_uri")

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
        } ?: throw InvalidRequest("no redirect_uri")
        return AuthenticationResponseResult.Redirect(url, response.params)
    }

    /**
     * Per OID4VP, the response must either be signed, or encrypted, or even signed and encrypted
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
        throw InvalidRequest("Response must be either signed, encrypted or both.")
    }

    private suspend fun sign(payload: AuthenticationResponseParameters): String =
        signJarm(null, payload, AuthenticationResponseParameters.serializer())
            .map { it.serialize() }
            .getOrElse {
                Napier.w("buildJarm error", it)
                throw InvalidRequest("buildJarm error", it)
            }.also {
                Napier.d("buildJarm: signed $payload")
            }

    private suspend fun encrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): String {
        val algorithm = response.clientMetadata!!.authorizationEncryptedResponseAlg!!
        val encryption = response.clientMetadata.authorizationEncryptedResponseEncoding!!
        val recipientKey = response.jsonWebKeys!!.getEcdhEsKey()
        val apv = request.parameters.nonce?.encodeToByteArray()
            ?: Random.nextBytes(16)
        val apu = response.mdocGeneratedNonce?.encodeToByteArray()
            ?: Random.nextBytes(16)
        val header = JweHeader(
            algorithm = algorithm,
            encryption = encryption,
            type = null, // TODO type?
            agreementPartyVInfo = apv,
            agreementPartyUInfo = apu,
            keyId = recipientKey.keyId,
        )
        val jwe = if (response.requestsSignature()) {
            sign(response.params).let { payload ->
                encryptJarm(header, payload, recipientKey)
                    .also { Napier.d("buildJarm: using $header to encrypt $payload") }
            }
        } else {
            encryptJarm(header, vckJsonSerializer.encodeToString(response.params), recipientKey)
                .also { Napier.d("buildJarm: using $header to encrypt ${response.params}") }
        }
        return jwe.map { it.serialize() }.getOrElse {
            Napier.w("buildJarm error", it)
            throw InvalidRequest("buildJarm error", it)
        }
    }

    @Throws(OAuth2Exception::class)
    private fun Collection<JsonWebKey>.getEcdhEsKey(): JsonWebKey =
        filter { it.type == JwkType.EC }.let { ecKeys ->
            ecKeys.firstOrNull { it.curve != null && it.algorithm == JweAlgorithm.ECDH_ES && it.publicKeyUse == "enc" }
                ?: ecKeys.firstOrNull { it.curve != null && it.publicKeyUse == "enc" }
                ?: ecKeys.firstOrNull { it.curve != null && it.algorithm == JweAlgorithm.ECDH_ES }
                ?: ecKeys.firstOrNull { it.curve != null }
                ?: throw InvalidRequest("no suitable ECDH ES key in $ecKeys")
        }

}

internal fun AuthenticationResponse.requestsEncryption(): Boolean =
    clientMetadata != null && jsonWebKeys != null && clientMetadata.requestsEncryption()

internal fun AuthenticationResponse.requestsSignature(): Boolean =
    clientMetadata != null && clientMetadata.authorizationSignedResponseAlg != null

internal fun RelyingPartyMetadata.requestsEncryption() =
    authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null
