package at.asitplus.wallet.lib.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.dcapi.OpenId4VpResponseMultiSigned
import at.asitplus.dcapi.OpenId4VpResponseSigned
import at.asitplus.dcapi.OpenId4VpResponseUnsigned
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.OpenIdConstants.ResponseMode.*
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.openid.encodeToParameters
import at.asitplus.openid.formUrlEncode
import io.ktor.http.*
import kotlin.coroutines.cancellation.CancellationException

internal class AuthenticationResponseFactory(
    val encryptResponse: EncryptJweFun,
    val randomSource: RandomSource = RandomSource.Secure,
) {

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun createAuthenticationResponse(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ): AuthenticationResponseResult = when (state.request.parameters.responseMode) {
        DirectPost -> authnResponseDirectPost(state, response)
        DirectPostJwt -> authnResponseDirectPostJwt(state, response)
        Query -> authnResponseQuery(state, response)
        Fragment, null -> authnResponseFragment(state, response)
        DcApi -> responseDcApi(state, response)
        DcApiJwt -> responseDcApi(state, response)
        is Other -> throw IllegalArgumentException("Unsupported response mode: ${state.request.parameters.responseMode}")
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun responseDcApi(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.DcApi(
        when (state.request) {
            is RequestParametersFrom.OpenId4VpDcApiUnsigned -> OpenId4VpResponseUnsigned(
                buildResponseParametersDcApi(state, response),
            )

            is RequestParametersFrom.OpenId4VpDcApiSigned -> OpenId4VpResponseSigned(
                buildResponseParametersDcApi(state, response)
            )

            is RequestParametersFrom.OpenId4VpDcApiMultiSigned -> OpenId4VpResponseMultiSigned(
                buildResponseParametersDcApi(state, response)
            )

            else -> throw IllegalStateException("Should only be called with DC API requests")
        }
    )

    @Throws(OAuth2Exception::class, CancellationException::class)
    internal suspend fun authnResponseDirectPostJwt(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Post(
        url = state.request.parameters.responseUrl
            ?: state.request.parameters.redirectUrlExtracted
            ?: throw InvalidRequest("no response_uri or redirect_uri"),
        params = AuthenticationResponseParameters(
            response = buildResponse(state, response),
        ).encodeToParameters()
    )

    @Throws(OAuth2Exception::class)
    internal fun authnResponseDirectPost(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Post(
        url = state.request.parameters.responseUrl
            ?: state.request.parameters.redirectUrlExtracted
            ?: throw InvalidRequest("no response_uri or redirect_uri"),
        params = when (response) {
            is AuthenticationResponse.Error -> response.error.encodeToParameters<OAuth2Error>()
            is AuthenticationResponse.Success -> response.params.encodeToParameters<AuthenticationResponseParameters>()
        }
    )

    @Throws(OAuth2Exception::class)
    internal fun authnResponseQuery(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Redirect(
        url = catchingUnwrapped {
            state.request.parameters.redirectUrlExtracted?.let { redirectUrl ->
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
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = AuthenticationResponseResult.Redirect(
        url = catchingUnwrapped {
            state.request.parameters.redirectUrlExtracted?.let { redirectUrl ->
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
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = if (state.responseRequiresEncryption) {
        encrypt(state, response)
    } else {
        when (response) {
            is AuthenticationResponse.Error -> joseCompliantSerializer.encodeToString(response.error)
            is AuthenticationResponse.Success -> joseCompliantSerializer.encodeToString(response.params)
        }
    }

    @Throws(OAuth2Exception::class, CancellationException::class)
    private suspend fun buildResponseParametersDcApi(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ) = if (state.responseRequiresEncryption) {
        AuthenticationResponseParameters(response = encrypt(state, response))
    } else {
        when (response) {
            is AuthenticationResponse.Error ->
                AuthenticationResponseParameters(response = joseCompliantSerializer.encodeToString(response.error))

            is AuthenticationResponse.Success -> response.params
        }
    }

    @Suppress("DEPRECATION")
    private suspend fun encrypt(
        state: AuthorizationResponsePreparationState,
        response: AuthenticationResponse,
    ): String {
        val recipientKey = state.jsonWebKeys?.getEncryptionTargetKey()
            ?: throw InvalidRequest("No suitable ECDH ES key found for response encryption")
        val algorithm = JweAlgorithm.ECDH_ES
        val encryption = state.clientMetadata?.encryptedResponseEncValues?.firstNotNullOfOrNull { it }
            ?: JweEncryption.A128GCM
        val apv = state.request.parameters.nonce?.encodeToByteArray() ?: randomSource.nextBytes(16)
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
                encryptResponse(header, joseCompliantSerializer.encodeToString(response.error), recipientKey)

            is AuthenticationResponse.Success ->
                encryptResponse(header, joseCompliantSerializer.encodeToString(response.params), recipientKey)
        }.map { it.serialize() }
            .getOrElse { throw InvalidRequest("encrypt error", it) }
    }

}

