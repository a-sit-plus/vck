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

            OpenIdConstants.ResponseMode.DIRECT_POST -> createDirectPostResponseModeParameters(request.parameters)
            OpenIdConstants.ResponseMode.DIRECT_POST_JWT -> createDirectPostJwtResponseModeParameters(
                request,
            )
            OpenIdConstants.ResponseMode.QUERY -> createQueryResponseModeParameters(request.parameters)

            is OpenIdConstants.ResponseMode.OTHER -> TODO()
        }
    }.wrap()

    private fun createDirectPostResponseModeParameters(requestParameters: AuthenticationRequestParameters): ResponseModeParameters.DirectPost {
        val responseUrl = validatePostTypeResponseModeParametersAndExtractResponseUrl(requestParameters)

        return ResponseModeParameters.DirectPost(
            responseUrl = responseUrl
        )
    }

    private fun createDirectPostJwtResponseModeParameters(
        request: AuthenticationRequest,
    ): ResponseModeParameters.DirectPostJwt {
        val responseUrl = validatePostTypeResponseModeParametersAndExtractResponseUrl(request.parameters)

        return ResponseModeParameters.DirectPostJwt(
            responseUrl = responseUrl,
        )
    }


    private fun createFragmentResponseModeParameters(requestParameters: AuthenticationRequestParameters): ResponseModeParameters.Fragment {
        if (requestParameters.redirectUrl == null) {
            Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is not set")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        return ResponseModeParameters.Fragment(
            redirectUrl = requestParameters.redirectUrl
        )
    }


    private fun createQueryResponseModeParameters(requestParameters: AuthenticationRequestParameters): ResponseModeParameters.Query {
        if (requestParameters.redirectUrl == null) {
            Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is not set")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        return ResponseModeParameters.Query(
            redirectUrl = requestParameters.redirectUrl
        )
    }





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