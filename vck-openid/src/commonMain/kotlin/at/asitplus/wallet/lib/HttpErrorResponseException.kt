package at.asitplus.wallet.lib

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.http.*
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

/**
 * A non-success HTTP response with its OAuth or RFC 9457 error details, when available.
 *
 * Extends [IllegalStateException], as its ktor-based predecessor did by extending ktor's `ResponseException`.
 */
open class HttpErrorResponseException(
    val status: HttpStatusCode,
    val headers: Headers,
    val responseBody: String,
    val oauth2Error: OAuth2Error?,
    val problemDetails: ProblemDetails?,
) : IllegalStateException() {

    /**
     * Parses [oauth2Error] from [responseBody], and [problemDetails] if the response has the media type
     * `application/problem+json`.
     */
    constructor(status: HttpStatusCode, headers: Headers, responseBody: String) :
            this(status, headers, responseBody, responseBody.toJsonObjectOrNull())

    private constructor(status: HttpStatusCode, headers: Headers, responseBody: String, json: JsonObject?) : this(
        status = status,
        headers = headers,
        responseBody = responseBody,
        oauth2Error = json?.toOAuth2ErrorOrNull(),
        problemDetails = json?.takeIf { headers.isProblemJson() }?.toProblemDetails(),
    )

    override val message: String = oauth2Error?.errorDescription
        ?: oauth2Error?.error
        ?: problemDetails?.detail
        ?: problemDetails?.title
        ?: responseBody.takeIf { it.isNotBlank() }
        ?: "HTTP $status"
}

private fun String.toJsonObjectOrNull(): JsonObject? = catchingUnwrapped {
    joseCompliantSerializer.parseToJsonElement(this).jsonObject
}.getOrNull()

private fun JsonObject.toOAuth2ErrorOrNull(): OAuth2Error? = catchingUnwrapped {
    joseCompliantSerializer.decodeFromJsonElement<OAuth2Error>(this)
}.getOrNull()

private fun Headers.isProblemJson(): Boolean = catchingUnwrapped {
    get(HttpHeaders.ContentType)?.let { ContentType.parse(it) }?.withoutParameters() == ContentType.Application.ProblemJson
}.getOrDefault(false)

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
