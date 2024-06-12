package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.oidc.AuthenticationRequest
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier


internal object ResponseModeParametersFactory {
    fun createResponseModeParameters(
        request: AuthenticationRequest,
    ): KmmResult<ResponseModeParameters> = KmmResult.runCatching {
        when (request.parameters.responseMode) {
            null, // default for vp_token and id_token is fragment
            OpenIdConstants.ResponseMode.FRAGMENT -> createFragmentResponseModeParameters(request.parameters)

            OpenIdConstants.ResponseMode.DIRECT_POST -> createDirectPostResponseModeParameters(
                request
            )

            OpenIdConstants.ResponseMode.DIRECT_POST_JWT -> createDirectPostJwtResponseModeParameters(
                request,
            )

            OpenIdConstants.ResponseMode.QUERY -> createQueryResponseModeParameters(request.parameters)

            is OpenIdConstants.ResponseMode.OTHER -> TODO()
        }
    }.wrap()

    private fun createDirectPostResponseModeParameters(request: AuthenticationRequest) =
        ResponseModeParameters.DirectPost(
            responseUrl = validatePostTypeResponseModeParametersAndExtractResponseUrl(request.parameters),
        )


    private fun createDirectPostJwtResponseModeParameters(request: AuthenticationRequest) =
        ResponseModeParameters.DirectPostJwt(
            responseUrl = validatePostTypeResponseModeParametersAndExtractResponseUrl(request.parameters),
        )


    private fun createFragmentResponseModeParameters(request: AuthenticationRequest) =
        ResponseModeParameters.Fragment(
            redirectUrl = request.parameters.redirectUrl ?: run {
                Napier.w("response_mode is ${request.parameters.responseMode}, but redirect_url is not set")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            },
        )


    private fun createQueryResponseModeParameters(request: AuthenticationRequest) =
        ResponseModeParameters.Query(
            redirectUrl = request.parameters.redirectUrl ?: run {
                Napier.w("response_mode is ${request.parameters.responseMode}, but redirect_url is not set")
                throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
            },
        )


    private fun validatePostTypeResponseModeParametersAndExtractResponseUrl(requestParameters: AuthenticationRequestParameters): String {
        if (requestParameters.redirectUrl != null) {
            Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is set")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        if (requestParameters.responseUrl == null) {
            Napier.w("response_mode is ${requestParameters.responseMode}, but response_url is not set")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        return requestParameters.responseUrl
    }
}