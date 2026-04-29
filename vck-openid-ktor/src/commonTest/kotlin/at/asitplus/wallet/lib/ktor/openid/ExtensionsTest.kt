package at.asitplus.wallet.lib.ktor.openid

import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*

val ExtensionsTest by testSuite {

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

    test("onFailure returns failure with OAuth2Error") {
        val expectedError = OAuth2Error(error = "invalid_client", errorDescription = "Nope")

        buildResponse(
            status = HttpStatusCode.BadRequest,
            body = joseCompliantSerializer.encodeToString(OAuth2Error.serializer(), expectedError),
            headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
        ).onFailure<OAuth2Error?> { _ -> this }
            .shouldBeInstanceOf<IntermediateResult.Failure<OAuth2Error?>>().apply {
                this.result shouldBe expectedError
            }
    }

    test("onSuccess unwraps response body") {
        val expectedBody = uuid4().toString()

        buildResponse(
            status = HttpStatusCode.OK,
            body = expectedBody,
            headers = headersOf(HttpHeaders.ContentType, ContentType.Text.Plain.toString())
        ).onFailure<String> { "failure" }
            .onSuccess<String, String> { this }.apply {
                this shouldBe expectedBody
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
