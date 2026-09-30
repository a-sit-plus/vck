package at.asitplus.wallet.lib

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

val HttpErrorResponseExceptionTest by matrixSuite {

    fun contentType(contentType: ContentType) = headersOf(HttpHeaders.ContentType, contentType.toString())

    test("OAuth error body is parsed") {
        val expectedError = OAuth2Error(error = "invalid_client", errorDescription = "Nope")
        val body = joseCompliantSerializer.encodeToString(OAuth2Error.serializer(), expectedError)

        HttpErrorResponseException(
            HttpStatusCode.BadRequest,
            contentType(ContentType.Application.Json),
            body
        ).apply {
            status shouldBe HttpStatusCode.BadRequest
            oauth2Error shouldBe expectedError
            problemDetails shouldBe null
            responseBody shouldBe body
            message shouldBe "Nope"
        }
    }

    test("RFC 9457 problem body is parsed with extensions") {
        val body = buildJsonObject {
            put("type", "https://example.com/problems/out-of-credit")
            put("title", "No credit")
            put("status", 403)
            put("detail", "Balance is too low")
            put("instance", "/accounts/123")
            put("balance", 30)
        }.toString()

        HttpErrorResponseException(
            HttpStatusCode.Forbidden,
            headersOf(HttpHeaders.ContentType, "application/problem+json; charset=utf-8"),
            body
        ).apply {
            oauth2Error shouldBe null
            problemDetails shouldBe ProblemDetails(
                type = "https://example.com/problems/out-of-credit",
                title = "No credit",
                status = 403,
                detail = "Balance is too low",
                instance = "/accounts/123",
                extensions = buildJsonObject { put("balance", 30) },
            )
            message shouldBe "Balance is too low"
        }
    }

    test("problem body without problem media type is not parsed as problem details") {
        HttpErrorResponseException(
            HttpStatusCode.BadRequest,
            contentType(ContentType.Application.Json),
            buildJsonObject { put("title", "No credit") }.toString()
        ).problemDetails shouldBe null
    }

    test("malformed content type does not prevent parsing") {
        HttpErrorResponseException(
            HttpStatusCode.BadRequest,
            headersOf(HttpHeaders.ContentType, "not a media type"),
            "{}"
        ).apply {
            oauth2Error shouldBe null
            problemDetails shouldBe null
        }
    }

    test("unstructured and empty bodies fall back to body and status in the message") {
        HttpErrorResponseException(
            HttpStatusCode.InternalServerError,
            contentType(ContentType.Text.Plain),
            "upstream failed"
        ).apply {
            oauth2Error shouldBe null
            problemDetails shouldBe null
            message shouldBe "upstream failed"
        }

        HttpErrorResponseException(HttpStatusCode.BadGateway, Headers.Empty, "")
            .message shouldBe "HTTP ${HttpStatusCode.BadGateway}"
    }

    test("is an IllegalStateException, like its ktor-based predecessor") {
        HttpErrorResponseException(HttpStatusCode.BadRequest, Headers.Empty, "")
            .shouldBeInstanceOf<IllegalStateException>()
    }
}
