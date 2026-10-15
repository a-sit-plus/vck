package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.HttpStep
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.content.*
import io.ktor.serialization.kotlinx.json.*

@Deprecated(
    "Moved to vck-openid, which does not depend on a ktor client",
    ReplaceWith("ProblemDetails", "at.asitplus.wallet.lib.ProblemDetails"),
)
typealias ProblemDetails = at.asitplus.wallet.lib.ProblemDetails

/**
 * A non-success HTTP response with its OAuth or RFC 9457 error details, when available,
 * as thrown by the ktor-based clients in this module.
 */
@Deprecated(
    "Moved to vck-openid, which does not depend on a ktor client",
    ReplaceWith("HttpErrorResponseException", "at.asitplus.wallet.lib.HttpErrorResponseException"),
)
typealias HttpErrorResponseException = at.asitplus.wallet.lib.HttpErrorResponseException

internal fun buildHttpClient(
    engine: HttpClientEngine,
    cookiesStorage: CookiesStorage? = null,
    httpClientConfig: (HttpClientConfig<*>.() -> Unit)? = null,
) = HttpClient(engine) {
    followRedirects = false
    install(ContentNegotiation) {
        json(joseCompliantSerializer)
    }
    install(DefaultRequest) {
        header(HttpHeaders.ContentType, ContentType.Application.Json)
    }
    httpClientConfig?.let { apply(it) }
    cookiesStorage?.let {
        install(HttpCookies) {
            storage = it
        }
    }
    installResponseValidation()
}

private fun HttpClientConfig<*>.installResponseValidation() {
    expectSuccess = true
    HttpResponseValidator {
        handleResponseExceptionWithRequest { cause, _ ->
            val response = (cause as? ResponseException)?.response
                ?: return@handleResponseExceptionWithRequest
            throw at.asitplus.wallet.lib.HttpErrorResponseException(
                response.status,
                response.headers,
                response.bodyAsText(),
            )
        }
    }
}

/**
 * Sends all requests of [exchange] with this client, and returns its result.
 *
 * Failures because of a non-success response are thrown as [at.asitplus.wallet.lib.HttpErrorResponseException].
 */
internal suspend fun <T> HttpClient.execute(exchange: HttpExchange<T>): T {
    var step = exchange.next().getOrThrow()
    while (step is HttpStep.Send) {
        val response = send(step.request.http)
        step = exchange.next(ReceivedHttpResponse(response.status, response.headers, response.bodyAsText()))
            .getOrThrow()
    }
    return (step as HttpStep.Done).value
}

/** Sends [prepared] without ktor's response validation, so that every status code reaches the exchange. */
internal suspend fun HttpClient.send(prepared: PreparedHttpRequest): HttpResponse = request(prepared.url) {
    method = prepared.method
    expectSuccess = false
    prepared.headers.forEach { name, values ->
        // the content type is set with the body, see below
        if (!name.equals(HttpHeaders.ContentType, ignoreCase = true)) values.forEach { headers.append(name, it) }
    }
    prepared.body?.let { body ->
        val contentType = prepared.headers[HttpHeaders.ContentType]?.let { ContentType.parse(it) }
            ?: ContentType.Text.Plain
        setBody(TextContent(body, contentType))
    }
}
