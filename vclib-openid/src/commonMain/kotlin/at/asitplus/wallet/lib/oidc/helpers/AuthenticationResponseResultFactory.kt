package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationResponseParameters
import at.asitplus.wallet.lib.oidc.AuthenticationResponseResult
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.github.aakira.napier.Napier
import io.ktor.http.URLBuilder


class AuthenticationResponseResultFactory(
    val jwsService: JwsService,
    val responseModeParameters: ResponseModeParameters,
    val responseParameters: AuthenticationResponseParameters,
) {
    suspend fun createAuthenticationResponseResult(): KmmResult<AuthenticationResponseResult> {
        return when (responseModeParameters) {
            is ResponseModeParameters.DirectPost -> KmmResult.success(
                AuthenticationResponseResult.Post(
                    url = responseModeParameters.responseUrl,
                    params = responseParameters.encodeToParameters(),
                )
            )

            is ResponseModeParameters.DirectPostJwt -> KmmResult.runCatching {
                authnResponseDirectPostJwt(
                    responseUrl = responseModeParameters.responseUrl,
                    responseParams = responseParameters,
                )
            }.wrap()

            is ResponseModeParameters.Query -> KmmResult.runCatching {
                authnResponseQuery(
                    redirectUrl = responseModeParameters.redirectUrl,
                    responseParams = responseParameters,
                )
            }.wrap()

            is ResponseModeParameters.Fragment -> KmmResult.runCatching {
                authnResponseFragment(
                    redirectUrl = responseModeParameters.redirectUrl,
                    responseParams = responseParameters,
                )
            }.wrap()
        }
    }

    private suspend fun authnResponseDirectPostJwt(
        responseUrl: String,
        responseParams: AuthenticationResponseParameters,
    ): AuthenticationResponseResult.Post {
        val responseParamsJws = jwsService.createSignedJwsAddingParams(
            payload = responseParams.serialize().encodeToByteArray(),
            addX5c = false,
        ).getOrElse {
            Napier.w("authnResponseDirectPostJwt error", it)
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        val jarm = AuthenticationResponseParameters(response = responseParamsJws.serialize())

        return AuthenticationResponseResult.Post(
            url = responseUrl,
            params = jarm.encodeToParameters(),
        )
    }

    private fun authnResponseQuery(
        redirectUrl: String,
        responseParams: AuthenticationResponseParameters,
    ): AuthenticationResponseResult.Redirect {
        val url = URLBuilder(redirectUrl).apply {
            responseParams.encodeToParameters().forEach {
                this.parameters.append(it.key, it.value)
            }
        }.buildString()

        return AuthenticationResponseResult.Redirect(
            url = url,
            params = responseParams,
        )
    }

    /**
     * That's the default for `id_token` and `vp_token`
     */
    private fun authnResponseFragment(
        redirectUrl: String, responseParams: AuthenticationResponseParameters
    ): AuthenticationResponseResult.Redirect {
        val url = URLBuilder(redirectUrl).apply {
            encodedFragment = responseParams.encodeToParameters().formUrlEncode()
        }.buildString()
        return AuthenticationResponseResult.Redirect(url, responseParams)
    }
}