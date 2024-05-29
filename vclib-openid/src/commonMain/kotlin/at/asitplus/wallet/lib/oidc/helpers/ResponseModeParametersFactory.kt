package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier


internal class ResponseModeParametersFactory(val requestParameters: AuthenticationRequestParameters) {
    fun createResponseModeParameters(): KmmResult<ResponseModeParameters> = KmmResult.runCatching {
        when (requestParameters.responseMode) {
            null, // default for vp_token and id_token is fragment
            OpenIdConstants.ResponseMode.FRAGMENT -> createFragmentResponseModeParameters()

            OpenIdConstants.ResponseMode.DIRECT_POST -> createDirectPostResponseModeParameters()
            OpenIdConstants.ResponseMode.DIRECT_POST_JWT -> createDirectPostJwtResponseModeParameters()
            OpenIdConstants.ResponseMode.QUERY -> createQueryResponseModeParameters()

            is OpenIdConstants.ResponseMode.OTHER -> TODO()
        }
    }.wrap()

    private fun createDirectPostResponseModeParameters(): ResponseModeParameters.DirectPost {
        val responseUrl = validatePostTypeResponseModeParametersAndExtractResponseUrl()

        return ResponseModeParameters.DirectPost(
            responseUrl = responseUrl
        )
    }

    private fun createDirectPostJwtResponseModeParameters(): ResponseModeParameters.DirectPostJwt {
        val responseUrl = validatePostTypeResponseModeParametersAndExtractResponseUrl()

        return ResponseModeParameters.DirectPostJwt(
            responseUrl = responseUrl
        )
    }


    private fun createFragmentResponseModeParameters(): ResponseModeParameters.Fragment {
        if (requestParameters.redirectUrl == null) {
            Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is not set")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        return ResponseModeParameters.Fragment(
            redirectUrl = requestParameters.redirectUrl
        )
    }


    private fun createQueryResponseModeParameters(): ResponseModeParameters.Query {
        if (requestParameters.redirectUrl == null) {
            Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is not set")
            throw OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST)
        }
        return ResponseModeParameters.Query(
            redirectUrl = requestParameters.redirectUrl
        )
    }





    private fun validatePostTypeResponseModeParametersAndExtractResponseUrl(): String {
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