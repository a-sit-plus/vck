package at.asitplus.wallet.lib.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwkType
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlin.coroutines.cancellation.CancellationException

internal class AuthenticationResponseFactory(
    val signJarm: SignJwtFun<AuthenticationResponseParameters>,
    val signError: SignJwtFun<OAuth2Error>,
    val encryptJarm: EncryptJweFun,
    val randomSource: RandomSource = RandomSource.Secure,
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
        DcApi -> responseDcApi(request, response, false)
        DcApiJwt -> responseDcApi(request, response, true)
        is Other -> TODO()
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun responseDcApi(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
        requestsEncryption: Boolean,
    ): AuthenticationResponseResult.DcApi {
        val responseSerialized = buildJarm(request, response, requestsEncryption)
        val jarm = AuthenticationResponseParameters(
            response = responseSerialized,
        )
        return AuthenticationResponseResult.DcApi(jarm)
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
        val params: Map<String, String> = response.params?.encodeToParameters()
            ?: response.error?.encodeToParameters()
            ?: throw InvalidRequest("nothing to encode")

        return AuthenticationResponseResult.Post(url, params)
    }

    @Throws(OAuth2Exception::class)
    internal fun authnResponseQuery(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Redirect {
        val url = catchingUnwrapped {
            request.parameters.redirectUrlExtracted?.let { redirectUrl ->
                URLBuilder(redirectUrl).apply {
                    response.params.encodeToParameters().forEach {
                        this.parameters.append(it.key, it.value)
                    }
                }.buildString()
            } ?: throw InvalidRequest("no redirect_uri")
        }.getOrElse {
            throw InvalidRequest("Unable to build url")
        }

        return AuthenticationResponseResult.Redirect(url, response.params ?: throw InvalidRequest("no params"))
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    @Throws(OAuth2Exception::class)
    internal fun authnResponseFragment(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult.Redirect {
        val url = catchingUnwrapped {
            request.parameters.redirectUrlExtracted?.let { redirectUrl ->
                URLBuilder(redirectUrl).apply {
                    encodedFragment = response.params.encodeToParameters().formUrlEncode()
                }.buildString()
            } ?: throw InvalidRequest("no redirect_uri")
        }.getOrElse {
            throw InvalidRequest("Unable to build url")
        }

        return AuthenticationResponseResult.Redirect(url, response.params ?: throw InvalidRequest("no params"))
    }

    /**
     * Per OID4VP, the response must either be signed, or encrypted, or even signed and encrypted
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun buildJarm(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
        requestsEncryption: Boolean = false,
    ) = if (response.requestsEncryption()) {
        encrypt(request, response)
    } else if (response.requestsSignature()) {
        response.params?.let { sign(it) } ?: throw InvalidRequest("No params in response")
    } else {
        if (requestsEncryption) {
            throw InvalidRequest("Invoker requests encryption but required parameters not set")
        }
        if (request.parameters.responseMode !is DcApi) {
            throw InvalidRequest("Response must be either signed, encrypted or both.")
        }
        joseCompliantSerializer.encodeToString(response.params ?: throw InvalidRequest("No params in response"))
    }

    private suspend fun sign(payload: AuthenticationResponseParameters): String =
        signJarm(null, payload, AuthenticationResponseParameters.serializer())
            .map { it.serialize() }
            .getOrElse { throw InvalidRequest("sign: error", it) }

    private suspend fun signError(payload: OAuth2Error): String =
        signError(null, payload, OAuth2Error.serializer())
            .map { it.serialize() }
            .getOrElse { throw InvalidRequest("signError: error", it) }

    private suspend fun encrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): String {
        val algorithm = response.clientMetadata!!.authorizationEncryptedResponseAlg!!
        val encryption = response.clientMetadata.authorizationEncryptedResponseEncoding!!
        val recipientKey = response.jsonWebKeys!!.getEcdhEsKey()
        val apv = request.parameters.nonce?.encodeToByteArray()
            ?: randomSource.nextBytes(16)
        val apu = response.mdocGeneratedNonce?.encodeToByteArray()
            ?: randomSource.nextBytes(16)
        val header = JweHeader(
            algorithm = algorithm,
            encryption = encryption,
            type = null, // TODO type?
            agreementPartyVInfo = apv,
            agreementPartyUInfo = apu,
            keyId = recipientKey.keyId,
        )
        val jwe = if (response.requestsSignature()) {
            val signature = response.params?.let { sign(it) }
                ?: response.error?.let { signError(it) }

            signature?.let { payload ->
                encryptJarm(header, payload, recipientKey)
                    .also { Napier.d("encrypt: using $header to encrypt $payload") }
            }
        } else {
            response.params?.let {
                encryptJarm(header, vckJsonSerializer.encodeToString(response.params), recipientKey)
                    .also { Napier.d("encrypt: using $header to encrypt ${response.params}") }
            } ?: response.error?.let {
                encryptJarm(header, vckJsonSerializer.encodeToString(response.error), recipientKey)
                    .also { Napier.d("encrypt: using $header to encrypt ${vckJsonSerializer.encodeToString(response.error)}") }
            } ?: throw InvalidRequest("encrypt: nothing to encrypt")
        }
        return jwe?.map { it.serialize() }
            ?.getOrElse { throw InvalidRequest("encrypt error", it) }
            ?: throw InvalidRequest("encrypt: nothing to serialize")
    }

    @Throws(OAuth2Exception::class)
    private fun Collection<JsonWebKey>.getEcdhEsKey(): JsonWebKey =
        filter { it.type == JwkType.EC }.let { ecKeys ->
            ecKeys.firstOrNull { it.publicKeyUse == "enc" }
                ?: ecKeys.firstOrNull { it.algorithm == JweAlgorithm.ECDH_ES }
                ?: ecKeys.firstOrNull()
                ?: throw InvalidRequest("no suitable ECDH ES key in $ecKeys")
        }

}

internal fun AuthenticationResponse.requestsEncryption(): Boolean =
    clientMetadata != null && jsonWebKeys != null && clientMetadata.requestsEncryption()

internal fun AuthenticationResponse.requestsSignature(): Boolean =
    clientMetadata != null && clientMetadata.authorizationSignedResponseAlg != null

internal fun RelyingPartyMetadata.requestsEncryption() =
    authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null
