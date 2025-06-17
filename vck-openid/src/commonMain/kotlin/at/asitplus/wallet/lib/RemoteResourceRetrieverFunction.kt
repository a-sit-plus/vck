package at.asitplus.wallet.lib

import at.asitplus.openid.RequestObjectParameters
import io.ktor.http.*

/**
 * Implementations need to fetch the url passed in, and return either the body, if there is one,
 * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
 */
typealias RemoteResourceRetrieverFunction = suspend (RemoteResourceRetrieverInput) -> String?

/**
 * Fetch the [url] with the [method], optionally sending [requestObjectParameters] or setting [headers] into HTTP request.
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
data class RemoteResourceRetrieverInput(
    val url: String,
    val method: HttpMethod = HttpMethod.Get,
    val headers: Map<String, String> = emptyMap<String, String>(),
    val requestObjectParameters: RequestObjectParameters? = null,
)
