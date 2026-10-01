package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.catchingUnwrapped
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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject

/**
 * Standard members of an
 * [RFC 9457 problem details object](https://datatracker.ietf.org/doc/html/rfc9457#name-the-problem-details-json-ob).
 * [type] defaults to `about:blank`; problem-specific members are retained in [extensions].
 */
data class ProblemDetails(
    val type: String = "about:blank",
    val status: Int? = null,
    val title: String? = null,
    val detail: String? = null,
    val instance: String? = null,
    val extensions: JsonObject = JsonObject(emptyMap()),
)

/** A non-success HTTP response with its OAuth or RFC 9457 error details, when available. */
class HttpErrorResponseException(
    response: HttpResponse,
    val responseBody: String,
    val oauth2Error: OAuth2Error?,
    val problemDetails: ProblemDetails?,
) : ResponseException(response, responseBody) {
    override val message = oauth2Error?.errorDescription
        ?: oauth2Error?.error
        ?: problemDetails?.detail
        ?: problemDetails?.title
        ?: responseBody.takeIf { it.isNotBlank() }
        ?: "HTTP ${response.status}"
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

private fun HttpClientConfig<*>.installResponseValidation() {
    expectSuccess = true
    HttpResponseValidator {
        handleResponseExceptionWithRequest { cause, _ ->
            val response = (cause as? ResponseException)?.response
                ?: return@handleResponseExceptionWithRequest
            val body = response.bodyAsText()
            val json = catchingUnwrapped {
                joseCompliantSerializer.parseToJsonElement(body).jsonObject
            }.getOrNull()

            throw HttpErrorResponseException(
                response = response,
                responseBody = body,
                oauth2Error = json?.let {
                    catchingUnwrapped {
                        joseCompliantSerializer.decodeFromJsonElement<OAuth2Error>(it)
                    }.getOrNull()
                },
                problemDetails = json?.takeIf {
                    response.contentType()?.withoutParameters() == ContentType.Application.ProblemJson
                }?.toProblemDetails(),
            )
        }
    }
}

private object SerialNames {
    const val TYPE = "type"
    const val TITLE = "title"
    const val STATUS = "status"
    const val DETAIL = "detail"
    const val INSTANCE = "instance"
    val AllMembers = setOf(TYPE, TITLE, STATUS, DETAIL, INSTANCE)
}

private fun JsonObject.toProblemDetails() = ProblemDetails(
    type = string(SerialNames.TYPE) ?: "about:blank",
    status = (get(SerialNames.STATUS) as? JsonPrimitive)
        ?.takeUnless { it.isString }
        ?.intOrNull
        ?.takeIf { it in 100..599 },
    title = string(SerialNames.TITLE),
    detail = string(SerialNames.DETAIL),
    instance = string(SerialNames.INSTANCE),
    extensions = JsonObject(filterKeys { it !in SerialNames.AllMembers }),
)

private fun JsonObject.string(name: String) = (get(name) as? JsonPrimitive)
    ?.takeIf { it.isString }
    ?.contentOrNull
