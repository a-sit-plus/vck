package at.asitplus.wallet.lib.oidc.helpers

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.github.aakira.napier.Napier


class ResponseModeParametersFactory(val requestParameters: AuthenticationRequestParameters) {
    fun createResponseModeParameters(): KmmResult<ResponseModeParameters> =
        when (requestParameters.responseMode) {
            OpenIdConstants.ResponseMode.DIRECT_POST -> createDirectPostResponseModeParameters()
            OpenIdConstants.ResponseMode.DIRECT_POST_JWT -> createDirectPostJwtResponseModeParameters()
            OpenIdConstants.ResponseMode.QUERY -> createQueryResponseModeParameters()

            // default for vp_token and id_token is fragment
            null, OpenIdConstants.ResponseMode.FRAGMENT -> createFragmentResponseModeParameters()
            else -> TODO()
        }.getOrElse {
            return KmmResult.failure(it)
        }.let {
            KmmResult.success(it)
        }

    private fun createDirectPostResponseModeParameters(): KmmResult<ResponseModeParameters.DirectPost> {
        val responseUrl =
            validatePostTypeResponseModeParametersAndExtractResponseUrl().getOrElse {
                return KmmResult.failure(it)
            }

        return KmmResult.success(
            ResponseModeParameters.DirectPost(
                responseUrl = responseUrl
            )
        )
    }

    private fun createDirectPostJwtResponseModeParameters(): KmmResult<ResponseModeParameters.DirectPostJwt> {
        val responseUrl =
            validatePostTypeResponseModeParametersAndExtractResponseUrl().getOrElse {
                return KmmResult.failure(it)
            }

        return KmmResult.success(
            ResponseModeParameters.DirectPostJwt(
                responseUrl = responseUrl
            )
        )
    }

    private fun validatePostTypeResponseModeParametersAndExtractResponseUrl(): KmmResult<String> {
        if (requestParameters.redirectUrl != null) {
            return KmmResult.failure(OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST).also {
                Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is set")
            })
        }
        if (requestParameters.responseUrl == null) {
            return KmmResult.failure(OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST).also {
                Napier.w("response_mode is ${requestParameters.responseMode}, but response_url is not set")
            })
        }
        return KmmResult.success(requestParameters.responseUrl)
    }


    private fun createFragmentResponseModeParameters(): KmmResult<ResponseModeParameters.Fragment> {
        if (requestParameters.redirectUrl == null) {
            return KmmResult.failure(OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST).also {
                Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is not set")
            })
        }
        return KmmResult.success(
            ResponseModeParameters.Fragment(
                redirectUrl = requestParameters.redirectUrl
            )
        )
    }


    private fun createQueryResponseModeParameters(): KmmResult<ResponseModeParameters.Query> {
        if (requestParameters.redirectUrl == null) {
            return KmmResult.failure(OAuth2Exception(OpenIdConstants.Errors.INVALID_REQUEST).also {
                Napier.w("response_mode is ${requestParameters.responseMode}, but redirect_url is not set")
            })
        }
        return KmmResult.success(
            ResponseModeParameters.Query(
                redirectUrl = requestParameters.redirectUrl
            )
        )
    }
}