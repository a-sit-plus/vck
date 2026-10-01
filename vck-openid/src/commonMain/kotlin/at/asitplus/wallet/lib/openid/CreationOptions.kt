package at.asitplus.wallet.lib.openid

import at.asitplus.openid.JarRequestParameters

/**
 * Options for creating authorization requests (query, by value, or by reference).
 * Use to control how the verifier delivers the request to the wallet.
 */
sealed class CreationOptions {
    /**
     * Creates authentication request with parameters encoded as URL query parameters to [walletUrl].
     */
    data class Query(val walletUrl: String) : CreationOptions()

    /**
     * Appends [requestUrl] to [walletUrl], callers need to call [CreatedRequest.loadRequestObject] with the
     * Wallet's request to actually create the authn request object, which will be unsigned.
     **/
    @Deprecated(
        "Forbidden by OpenID4VP 1.0, 5.10.1: the request URI response MUST be a signed request object. The " +
                "redirect_uri prefix, the only one that cannot sign, therefore cannot use by-reference at all.",
        ReplaceWith("SignedRequestByReference(walletUrl, requestUrl, requestUrlMethod)"),
        level = DeprecationLevel.ERROR,
    )
    data class RequestByReference(
        val walletUrl: String,
        val requestUrl: String,
        val requestUrlMethod: JarRequestParameters.RequestUriMethod = JarRequestParameters.RequestUriMethod.GET,
    ) : CreationOptions()

    /** Appends authentication request as signed object to [walletUrl] */
    data class SignedRequestByValue(val walletUrl: String) : CreationOptions()

    /**
     * Appends [requestUrl] to [walletUrl], callers need to call [CreatedRequest.loadRequestObject] with the
     * Wallet's request to actually create the authn request object (which will be signed).
     */
    data class SignedRequestByReference(
        val walletUrl: String,
        val requestUrl: String,
        val requestUrlMethod: JarRequestParameters.RequestUriMethod = JarRequestParameters.RequestUriMethod.GET,
    ) : CreationOptions()
}