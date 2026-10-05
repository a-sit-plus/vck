package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.openid.RequestObjectParameters

data class CreatedRequest(
    /** URL to invoke the wallet, may be rendered as a QR Code. */
    val url: String,
    /**
     *  Optional content that needs to be served under the previously passed in `requestUrl`
     *  (see [CreationOptions.SignedRequestByReference.requestUrl] in call to [OpenId4VpVerifier.createAuthnRequest]);
     *  serve it with [loadRequestObjectHttpResponse], which sets the content type.
     *
     *  Pass in the [at.asitplus.openid.RequestObjectParameters] that the Wallet may have sent when requesting the request object.
     */
    val loadRequestObject: (suspend (RequestObjectParameters?) -> KmmResult<String>)? = null,
)