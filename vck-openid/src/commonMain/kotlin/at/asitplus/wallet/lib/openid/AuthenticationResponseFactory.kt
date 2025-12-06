package at.asitplus.wallet.lib.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.OpenId4VpResponseSigned
import at.asitplus.dcapi.OpenId4VpResponseUnsigned
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.ktor.http.*
import kotlin.coroutines.cancellation.CancellationException

internal class AuthenticationResponseFactory(
    val encryptResponse: EncryptJweFun,
    val randomSource: RandomSource = RandomSource.Secure,
) {
    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun createAuthenticationResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult = when (request.parameters.responseMode) {
        DirectPost -> authnResponseDirectPost(request, response)
        DirectPostJwt -> authnResponseDirectPostJwt(request, response)
        Query -> authnResponseQuery(request, response)
        Fragment, null -> authnResponseFragment(request, response)
        DcApi -> responseDcApi(request, response)
        DcApiJwt -> responseDcApi(request, response)
        is Other -> throw IllegalArgumentException("Unsupported response mode: ${request.parameters.responseMode}")
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun responseDcApi(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.DcApi(
        when (request) {
            is RequestParametersFrom.DcApiUnsigned<*> -> OpenId4VpResponseUnsigned(
                buildResponseParametersDcApi(request, response),
            )

            is RequestParametersFrom.DcApiSigned<*> -> OpenId4VpResponseSigned(
                buildResponseParametersDcApi(request, response)
            )

            else -> throw IllegalStateException("Should only be called with DC API requests")
        }
    )

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun authnResponseDirectPostJwt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Post(
        url = request.parameters.responseUrl
            ?: request.parameters.redirectUrlExtracted
            ?: throw InvalidRequest("no response_uri or redirect_uri"),
        params = AuthenticationResponseParameters(
            response = buildResponse(request, response),
        ).encodeToParameters()
    )

    @Throws(OAuth2Exception::class)
    internal fun authnResponseDirectPost(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Post(
        url = request.parameters.responseUrl
            ?: request.parameters.redirectUrlExtracted
            ?: throw InvalidRequest("no response_uri or redirect_uri"),
        params = when (response) {
            is AuthenticationResponse.Error -> response.error.encodeToParameters<OAuth2Error>()
            is AuthenticationResponse.Success -> response.params.encodeToParameters<AuthenticationResponseParameters>()
        }
    )

    @Throws(OAuth2Exception::class)
    internal fun authnResponseQuery(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Redirect(
        url = catchingUnwrapped {
            request.parameters.redirectUrlExtracted?.let { redirectUrl ->
                URLBuilder(redirectUrl).apply {
                    appendParameters(response)
                }.buildString()
            } ?: throw InvalidRequest("no redirect_uri")
        }.getOrElse {
            throw InvalidRequest("Unable to build url", it)
        },
        params = (response as? AuthenticationResponse.Success)?.params,
        error = (response as? AuthenticationResponse.Error)?.error
    )

    private fun URLBuilder.appendParameters(response: AuthenticationResponse) {
        when (response) {
            is AuthenticationResponse.Error -> response.error.encodeToParameters()
            is AuthenticationResponse.Success -> response.params.encodeToParameters()
        }.forEach {
            parameters.append(it.key, it.value)
        }
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    @Throws(OAuth2Exception::class)
    internal fun authnResponseFragment(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Redirect(
        url = catchingUnwrapped {
            request.parameters.redirectUrlExtracted?.let { redirectUrl ->
                URLBuilder(redirectUrl).apply {
                    setFragment(response)
                }.buildString()
            } ?: throw InvalidRequest("no redirect_uri")
        }.getOrElse {
            throw InvalidRequest("Unable to build url")
        },
        params = (response as? AuthenticationResponse.Success)?.params,
        error = (response as? AuthenticationResponse.Error)?.error
    )

    private fun URLBuilder.setFragment(response: AuthenticationResponse) {
        encodedFragment = when (response) {
            is AuthenticationResponse.Error -> response.error.encodeToParameters().formUrlEncode()
            is AuthenticationResponse.Success -> response.params.encodeToParameters().formUrlEncode()
        }
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun buildResponse(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) =  if (request.parameters.responseMode?.requiresEncryption == true || response.requestsEncryption()) {
            encrypt(request, response)
        } else {
            when (response) {
                is AuthenticationResponse.Error -> joseCompliantSerializer.encodeToString(response.error)
                is AuthenticationResponse.Success -> joseCompliantSerializer.encodeToString(response.params)
            }
        }

    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun buildResponseParametersDcApi(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ) = if (request.parameters.responseMode?.requiresEncryption == true || response.requestsEncryption()) {
        AuthenticationResponseParameters(response = encrypt(request, response))
    } else {
        when (response) {
            is AuthenticationResponse.Error ->
                AuthenticationResponseParameters(response = joseCompliantSerializer.encodeToString(response.error))
            is AuthenticationResponse.Success -> response.params
        }
    }

    @Suppress("DEPRECATION")
    private suspend fun encrypt(
        request: RequestParametersFrom<AuthenticationRequestParameters>,
        response: AuthenticationResponse,
    ): String {
        val recipientKey = response.jsonWebKeys?.getEncryptionTargetKey()
            ?: throw InvalidRequest("no suitable ECDH ES key found")
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = response.clientMetadata?.encryptedResponseEncValues?.firstNotNullOfOrNull { it }
            ?: response.clientMetadata?.authorizationEncryptedResponseEncoding
            ?: JweEncryption.A128GCM
        val apv = request.parameters.nonce?.encodeToByteArray() ?: randomSource.nextBytes(16)
        val apu = randomSource.nextBytes(16)
        val header = JweHeader(
            algorithm = algorithm,
            encryption = encryption,
            agreementPartyVInfo = apv,
            agreementPartyUInfo = apu,
            keyId = recipientKey.keyId,
        )
        return when (response) {
            is AuthenticationResponse.Error ->
                encryptResponse(header, vckJsonSerializer.encodeToString(response.error), recipientKey)

            is AuthenticationResponse.Success ->
                encryptResponse(header, vckJsonSerializer.encodeToString(response.params), recipientKey)
        }.map { it.serialize() }
            .getOrElse { throw InvalidRequest("encrypt error", it) }
    }

}

internal fun AuthenticationResponse.requestsEncryption(): Boolean =
    (clientMetadata != null && jsonWebKeys != null && clientMetadata.requestsEncryption())

@Suppress("DEPRECATION")
internal fun RelyingPartyMetadata.requestsEncryption() =
    (authorizationEncryptedResponseAlg != null && authorizationEncryptedResponseEncoding != null)
            || (encryptedResponseEncValues != null)
