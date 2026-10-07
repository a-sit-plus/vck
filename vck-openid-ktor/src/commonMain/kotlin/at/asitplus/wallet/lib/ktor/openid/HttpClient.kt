package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.HttpExchange
import at.asitplus.wallet.lib.HttpStep
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Error
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
    "Catch at.asitplus.wallet.lib.HttpErrorResponseException, which this class extends; use its status and headers " +
            "instead of the ktor response. This class no longer extends ktor's ResponseException.",
    ReplaceWith("HttpErrorResponseException", "at.asitplus.wallet.lib.HttpErrorResponseException"),
)
class HttpErrorResponseException : at.asitplus.wallet.lib.HttpErrorResponseException {

    /** The ktor response; use [status] and [headers] instead. */
    val response: HttpResponse

    constructor(
        response: HttpResponse,
        responseBody: String,
        oauth2Error: OAuth2Error?,
        problemDetails: at.asitplus.wallet.lib.ProblemDetails?,
    ) : super(response.status, response.headers, responseBody, oauth2Error, problemDetails) {
        this.response = response
    }

    /** Parses the OAuth and RFC 9457 error details from [responseBody]. */
    internal constructor(response: HttpResponse, responseBody: String) :
            super(response.status, response.headers, responseBody) {
        this.response = response
    }
}

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

@Suppress("DEPRECATION") // keeps throwing the ktor subclass until it is removed
private fun HttpClientConfig<*>.installResponseValidation() {
    expectSuccess = true
    HttpResponseValidator {
        handleResponseExceptionWithRequest { cause, _ ->
            val response = (cause as? ResponseException)?.response
                ?: return@handleResponseExceptionWithRequest
            throw HttpErrorResponseException(response, response.bodyAsText())
        }
    }
}

/**
 * Sends all requests of [exchange] with this client, and returns its result.
 *
 * Failures because of a non-success response are thrown as the deprecated [HttpErrorResponseException] of this module
 * (built from the last ktor response), so that callers catching it keep catching everything until it is removed.
 */
@Suppress("DEPRECATION")
internal suspend fun <T> HttpClient.execute(exchange: HttpExchange<T>): T {
    var lastResponse: HttpResponse? = null
    try {
        var step = exchange.next().getOrThrow()
        while (step is HttpStep.Send) {
            val response = send(step.request.http)
            lastResponse = response
            step = exchange.next(ReceivedHttpResponse(response.status, response.headers, response.bodyAsText()))
                .getOrThrow()
        }
        return (step as HttpStep.Done).value
    } catch (error: at.asitplus.wallet.lib.HttpErrorResponseException) {
        throw lastResponse
            ?.let { HttpErrorResponseException(it, error.responseBody, error.oauth2Error, error.problemDetails) }
            ?: error
    }
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
