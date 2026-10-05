package at.asitplus.wallet.lib

import at.asitplus.openid.RequestObjectParameters
import io.ktor.http.*
import kotlin.jvm.JvmOverloads

/**
 * Implementations need to fetch the url passed in, and return either the body, if there is one,
 * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
 *
 * Wallets don't need it: [at.asitplus.wallet.lib.openid.OpenId4VpProtocolClient] and
 * [at.asitplus.wallet.lib.oidvci.OpenId4VciProtocolClient] fetch request objects and credential offers passed by
 * reference with [HttpExchange]s, which can also report status codes and headers.
 */
typealias RemoteResourceRetrieverFunction = suspend (RemoteResourceRetrieverInput) -> String?

/**
 * Fetch the [url] with the [method], send [requestObjectParameters] and set [headers] for that HTTP request.
 *
 * Example for ktor (`data` being this object):
 *
 * ```
 * client.submitForm(
 *   url = data.url,
 *   formParameters = parameters {
 *     data.requestObjectParameters?.encodeToParameters()?.forEach { append(it.key, it.value) }
 *   }
 * ) {
 *   data.headers.forEach { headers[it.key] = it.value }
 * }.bodyAsText()
 * ```
 *
 * or
 *
 * ```
 * client.get(URLBuilder(data.url).apply {
 *   data.requestObjectParameters?.encodeToParameters()
 *     ?.forEach { parameters.append(it.key, it.value) }
 * }.build()) {
 *   data.headers.forEach { headers[it.key] = it.value }
 * }.bodyAsText()
 * ```
 */
data class RemoteResourceRetrieverInput @JvmOverloads constructor(
    val url: String,
    val method: HttpMethod = HttpMethod.Get,
    val headers: Map<String, String> = emptyMap<String, String>(),
    val requestObjectParameters: RequestObjectParameters? = null,
)
