package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import at.asitplus.wallet.lib.oidvci.formUrlEncode
import io.ktor.http.URLBuilder
import io.ktor.http.Url

/**
 * Container for an OIDC Authentication Response
 */
data class AuthenticationResponse(
    val url: String,
    val params: AuthenticationResponseParameters,
) {

    fun toUrl(): String {
        val urlBuilder = URLBuilder(url)
        urlBuilder.encodedFragment = params.encodeToParameters().formUrlEncode()
        return urlBuilder.buildString()
    }

    companion object {
        /**
         * Expects [AuthenticationResponseParameters] as the Fragment of the URL in [it],
         * e.g. `https://example.com#id_token=..."
         */
        fun parseUrl(it: String): AuthenticationResponse? {
            val url = kotlin.runCatching { Url(it) }.getOrNull()
                ?: return null
            val params: AuthenticationResponseParameters = url.fragment.decodeFromPostBody()
            return AuthenticationResponse(
                url = "${url.protocol}://${url.host}${url.encodedPath}",
                params = params
            )
        }
    }
}