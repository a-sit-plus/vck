package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

val ExtensionsTest by matrixSuite {

    suspend fun buildResponse(
        status: HttpStatusCode,
        body: String,
        headers: Headers = headersOf(),
    ): io.ktor.client.statement.HttpResponse {
        val client = HttpClient(MockEngine { respond(body, status = status, headers = headers) }) {
            install(ContentNegotiation) {
                json(joseCompliantSerializer)
            }
        }
        return try {
            client.get("https://example.com")
        } finally {
            client.close()
        }
    }

    suspend fun requestWithValidation(
        status: HttpStatusCode,
        body: String,
        contentType: ContentType,
    ) = buildHttpClient(MockEngine {
        respond(
            content = body,
            status = status,
            headers = headersOf(HttpHeaders.ContentType, contentType.toString()),
        )
    }).let { client ->
        try {
            client.get("https://example.com")
        } finally {
            client.close()
        }
    }

    test("successful response is returned") {
        requestWithValidation(HttpStatusCode.OK, "ok", ContentType.Text.Plain).bodyAsText() shouldBe "ok"
    }

    test("OAuth error response is preserved") {
        val expectedError = OAuth2Error(error = "invalid_client", errorDescription = "Nope")
        val body = joseCompliantSerializer.encodeToString(OAuth2Error.serializer(), expectedError)

        shouldThrow<HttpErrorResponseException> {
            requestWithValidation(HttpStatusCode.BadRequest, body, ContentType.Application.Json)
        }.apply {
            oauth2Error shouldBe expectedError
            problemDetails shouldBe null
            responseBody shouldBe body
        }
    }

    test("RFC 9457 problem response is preserved with extensions") {
        val problem = buildJsonObject {
            put("type", "https://example.com/problems/out-of-credit")
            put("title", "No credit")
            put("status", 403)
            put("detail", "Balance is too low")
            put("instance", "/accounts/123")
            put("balance", 30)
        }
        val body = problem.toString()

        shouldThrow<HttpErrorResponseException> {
            requestWithValidation(
                HttpStatusCode.Forbidden,
                body,
                ContentType.parse("application/problem+json"),
            )
        }.apply {
            oauth2Error shouldBe null
            problemDetails shouldBe ProblemDetails(
                type = "https://example.com/problems/out-of-credit",
                title = "No credit",
                status = 403,
                detail = "Balance is too low",
                instance = "/accounts/123",
                extensions = buildJsonObject { put("balance", 30) },
            )
            responseBody shouldBe body
            message shouldBe "Balance is too low"
        }
    }

    test("RFC 9457 problem response uses the default type") {
        shouldThrow<HttpErrorResponseException> {
            requestWithValidation(
                HttpStatusCode.BadRequest,
                "{}",
                ContentType.Application.ProblemJson,
            )
        }.problemDetails shouldBe ProblemDetails()
    }

    test("unstructured error response is preserved") {
        shouldThrow<HttpErrorResponseException> {
            requestWithValidation(HttpStatusCode.InternalServerError, "upstream failed", ContentType.Text.Plain)
        }.apply {
            oauth2Error shouldBe null
            problemDetails shouldBe null
            responseBody shouldBe "upstream failed"
        }
    }

    test("dpopNonce extracts nonce from error or WWW-Authenticate") {
        val authServerNonce = uuid4().toString()
        val authServerResponse = buildResponse(
            status = HttpStatusCode.BadRequest,
            body = joseCompliantSerializer.encodeToString(OAuth2Error.serializer(), OAuth2Error(error = USE_DPOP_NONCE)),
            headers = headers {
                append(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                append(HttpHeaders.DPoPNonce, authServerNonce)
            }
        )

        OAuth2Error(error = USE_DPOP_NONCE).dpopNonce(authServerResponse) shouldBe authServerNonce

        val resourceServerNonce = uuid4().toString()
        val resourceServerResponse = buildResponse(
            status = HttpStatusCode.Unauthorized,
            body = "",
            headers = headers {
                append(HttpHeaders.WWWAuthenticate, "Bearer error=\"$USE_DPOP_NONCE\"")
                append(HttpHeaders.DPoPNonce, resourceServerNonce)
            }
        )

        null.dpopNonce(resourceServerResponse) shouldBe resourceServerNonce
    }
}
