package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Duration

/**
 * Contents of a response to a pushed authorization request,
 * see [OAuth 2.0 Pushed Authorization Requests](https://www.rfc-editor.org/rfc/rfc9126.html)
 */
@Serializable
data class PushedAuthenticationResponseParameters(
    /**
     * The request URI corresponding to the authorization request posted. This URI is a single-use reference to the
     * respective request data in the subsequent authorization request. The way the authorization process obtains the
     * authorization request data is at the discretion of the authorization server and is out of scope of this
     * specification. There is no need to make the authorization request data available to other parties via this URI.
     */
    @SerialName("request_uri")
    val requestUri: String? = null,

    /**
     * A JSON number that represents the lifetime of the request URI in seconds as a positive integer. The request URI
     * lifetime is at the discretion of the authorization server but will typically be relatively short (e.g.,
     * between 5 and 600 seconds).
     */
    @SerialName("expires_in")
    @Serializable(with = DurationSecondsIntSerializer::class)
    val expires: Duration? = null,
)