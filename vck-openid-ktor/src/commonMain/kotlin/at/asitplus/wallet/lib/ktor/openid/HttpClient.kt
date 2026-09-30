package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.client.*
import io.ktor.client.engine.*
import io.ktor.client.plugins.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.plugins.cookies.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
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
