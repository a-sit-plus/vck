package at.asitplus.wallet.lib.openid

import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
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
        DirectPostJwt -> authnResponseDirectPostJwt(request, response, true)
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
        requestsEncryption: Boolean
    ) : AuthenticationResponseResult.DcApi {

        val responseSerialized = buildResponse(request, response, requestsEncryption)
        val jarm = AuthenticationResponseParameters(
            response = responseSerialized,
        )
        return AuthenticationResponseResult.DcApi(jarm)
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun authnResponseDirectPostJwt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
        requestsEncryption: Boolean
    ): AuthenticationResponseResult.Post {
        val url = request.parameters.responseUrl
            ?: request.parameters.redirectUrlExtracted
            ?: throw InvalidRequest("no response_uri or redirect_uri")
        val responseSerialized = buildResponse(request, response, requestsEncryption)
        val jarm = AuthenticationResponseParameters(
            // Everybody knows this is wrong, but EUDIW reference implementation required this some time ago
            // so for maximum compatibility with those verifiers we'll include it
            state = request.parameters.state,
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


    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun buildResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
        requestsEncryption: Boolean = false
    ) = if (response.requestsLegacyEncryption()) {
        legacyEncrypt(request, response)
    } else if (response.requiredFieldsForEncryptionSet() && requestsEncryption) {
        encrypt(request, response)
    } else if (response.requestsSignature()) {
        sign(response.params)
    } else {
        if (requestsEncryption) {
            throw InvalidRequest("Invoker requests encryption but required parameters not set")
        }
        if (request.parameters.responseMode !is DcApi) {
            throw InvalidRequest("Response must be either signed, encrypted or both.")
        }
        response.params.serialize()
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

    @Deprecated("Used attributes are removed from OpenID4VP Draft 26", replaceWith = ReplaceWith("encrypt(RequestParametersFrom<AuthenticationRequestParameters>, AuthenticationResponse)"))
    private suspend fun legacyEncrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse
    ): String {
        val algorithm = response.clientMetadata!!.authorizationEncryptedResponseAlg!!
        val encryption = response.clientMetadata.authorizationEncryptedResponseEncoding!!
        return encrypt(request, response, algorithm, encryption)
    }

    private suspend fun encrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): String {
        val encryption = response.clientMetadata!!.encryptedResponseEncoding!!
        //val key = response.jsonWebKeys!!.firstOrNull { it.algorithm == encryption }
        val key = response.jsonWebKeys!!.firstOrNull { it.algorithm != null }

        val jsonWebAlgorithm = key!!.algorithm
        val jweAlgorithm = JweAlgorithm.entries.firstOrNull { it.identifier == jsonWebAlgorithm!!.identifier }

        return encrypt(request, response, jweAlgorithm!!, encryption) //TODO throw on not found
    }

    private suspend fun encrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
        algorithm: JweAlgorithm,
        encryption: JweEncryption,
        ): String {
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
            ecKeys.firstOrNull { it.publicKeyUse == "enc" }
                ?: ecKeys.firstOrNull { it.algorithm == JweAlgorithm.ECDH_ES }
                ?: ecKeys.firstOrNull()
                ?: throw InvalidRequest("no suitable ECDH ES key in $ecKeys")
        }

}

internal fun AuthenticationResponse.requiredFieldsForEncryptionSet(): Boolean
    {
    //jsonWebKeys!!.first().algorithm = ""
    return clientMetadata != null && jsonWebKeys != null && jsonWebKeys.any { it.algorithm != null } && clientMetadata.encryptionSupported() }

internal fun AuthenticationResponse.requestsLegacyEncryption(): Boolean =
    clientMetadata != null && jsonWebKeys != null && clientMetadata.requestsLegacyEncryption()

internal fun AuthenticationResponse.requestsSignature(): Boolean =
    clientMetadata != null && clientMetadata.authorizationSignedResponseAlg != null

internal fun RelyingPartyMetadata.encryptionSupported() =
    encryptedResponseEncoding != null

internal fun RelyingPartyMetadata.requestsLegacyEncryption() =
    authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null
