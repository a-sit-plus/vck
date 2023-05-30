package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import io.ktor.http.URLBuilder
import io.ktor.http.Url
import io.ktor.util.flattenEntries

/**
 * Container for a OIDC Authentication Request
 */
data class AuthenticationRequest(
    val url: String,
    val params: AuthenticationRequestParameters,
) {

    fun toUrl(): String {
        val urlBuilder = URLBuilder(url)
        params.encodeToParameters().forEach { urlBuilder.parameters.append(it.key, it.value) }
        return urlBuilder.buildString()
    }

    companion object {
        /**
         * Expects [AuthenticationRequestParameters] as the parameters of the URL in [it],
         * e.g. `https://example.com?response_type=..."
         */
        fun parseUrl(it: String): AuthenticationRequest? {
            val url = kotlin.runCatching { Url(it) }.getOrNull()
                ?: return null
            val params: AuthenticationRequestParameters = url.parameters.flattenEntries().toMap().decodeFromUrlQuery()
            return AuthenticationRequest(
                url = "${url.protocol}://${url.host}${url.encodedPath}",
                params = params
            )
        }
    }

}