package at.asitplus.wallet.lib.openid

import at.asitplus.catching
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.MediaTypes
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.http.*

val OpenId4VpVerifierResponsesTest by matrixSuite {

    testSuite("request object") {
        test("is served as application/oauth-authz-req+jwt, loaded for the parameters of the wallet") {
            val params = RequestObjectParameters(walletNonce = "wallet-nonce")
            var loadedFor: RequestObjectParameters? = null
            val request = CreatedRequest("https://wallet.example.com/") {
                catching { "request-object-for-${it?.walletNonce}".also { _ -> loadedFor = it } }
            }

            request.loadRequestObjectHttpResponse(params).getOrThrow().apply {
                status shouldBe HttpStatusCode.OK
                headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.AUTHZ_REQ_JWT
                body shouldBe "request-object-for-wallet-nonce"
            }
            loadedFor shouldBe params
        }

        test("fails for a request without request object") {
            CreatedRequest("https://wallet.example.com/").loadRequestObjectHttpResponse(null)
                .exceptionOrNull().shouldBeInstanceOf<IllegalStateException>()
        }

        test("fails when loading the request object fails") {
            CreatedRequest("https://wallet.example.com/") { catching { throw IllegalArgumentException("unknown") } }
                .loadRequestObjectHttpResponse(null)
                .exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
        }
    }

    testSuite("answer of the response endpoint") {
        test("with redirect_uri, not cached") {
            val redirectUri = "https://verifier.example.com/cb#response_code=abc"

            directPostHttpResponse(redirectUri).apply {
                status shouldBe HttpStatusCode.OK
                headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JSON
                headers[HttpHeaders.CacheControl] shouldBe "no-store"
                joseCompliantSerializer.decodeFromString<OpenId4VpSuccess>(body) shouldBe OpenId4VpSuccess(redirectUri)
            }
        }

        test("without redirect_uri, an empty JSON object") {
            directPostHttpResponse().apply {
                status shouldBe HttpStatusCode.OK
                headers[HttpHeaders.ContentType] shouldBe MediaTypes.Application.JSON
                headers[HttpHeaders.CacheControl] shouldBe "no-store"
                body shouldBe "{}"
            }
        }
    }
}
