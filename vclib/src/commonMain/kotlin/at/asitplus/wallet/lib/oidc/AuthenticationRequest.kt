package at.asitplus.wallet.lib.oidc

import io.ktor.http.*
import io.ktor.util.*

/**
 * Container for a OIDC Authentication Request
 */
data class AuthenticationRequest(
    val url: String,
    val params: AuthenticationRequestParameters,
) {

    fun toUrl(): String {
        val urlBuilder = URLBuilder(url)
        params.serialize()
            .forEach { (k, v) -> urlBuilder.parameters[k] = v.toString() }
        return urlBuilder.buildString()
    }

    companion object {
        fun parseUrl(it: String): AuthenticationRequest? {
            val url = kotlin.runCatching { Url(it) }.getOrNull()
                ?: return null
            val params = AuthenticationRequestParameters.deserialize(
                url.parameters.flattenEntries().toMap()
            ) ?: return null
            return AuthenticationRequest(
                url = "${url.protocol}://${url.host}${url.encodedPath}",
                params = params
            )
        }
    }

}