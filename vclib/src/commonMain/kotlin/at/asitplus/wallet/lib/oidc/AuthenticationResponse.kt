package at.asitplus.wallet.lib.oidc

import io.ktor.http.*

/**
 * Container for an OIDC Authentication Response
 */
data class AuthenticationResponse(
    val url: String,
    val params: AuthenticationResponseParameters,
) {

    fun toUrl(): String {
        val urlBuilder = URLBuilder(url)
        val parameters = Parameters.build {
            params.serialize().forEach { (k, v) -> this[k] = v.toString() }
        }
        urlBuilder.encodedFragment = parameters.formUrlEncode()
        return urlBuilder.buildString()
    }

    companion object {
        fun parseUrl(it: String): AuthenticationResponse? {
            val url = kotlin.runCatching { Url(it) }.getOrNull()
                ?: return null
            val params = AuthenticationResponseParameters.deserialize(
                url.fragment.split("&")
                    .associate { param ->
                        val split = param.split("=")
                        split[0] to param.replace(split[0] + "=", "")
                    }
            ) ?: return null
            return AuthenticationResponse(
                url = "${url.protocol}://${url.host}${url.encodedPath}",
                params = params
            )
        }
    }
}