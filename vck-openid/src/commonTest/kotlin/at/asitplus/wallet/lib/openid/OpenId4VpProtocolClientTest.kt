package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants.Errors.INVALID_REQUEST
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpErrorResponseException
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.oauth2.FakeHttpStack
import at.asitplus.wallet.lib.oauth2.formParameters
import at.asitplus.wallet.lib.oauth2.jsonResponse
import at.asitplus.wallet.lib.oauth2.kinds
import at.asitplus.wallet.lib.oauth2.scripted
import at.asitplus.wallet.lib.oauth2.toErrorResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.ktor.http.*

val OpenId4VpProtocolClientTest by matrixSuite {

    fun client() = OpenId4VpHolder().let {
        OpenId4VpProtocolClient(openId4VpHolder = it, dcApiHolder = DcApiHolder(openId4VpHolder = it))
    }

    val response = AuthenticationResponseResult.Post(
        url = "https://verifier.example.com/response",
        params = mapOf("response" to "eyJhbGciOiJFQ0RILUVTIn0.e30..", "state" to "a b&c=d"),
    )

    fun plainAnswer(body: String, headers: Headers = Headers.Empty) =
        ReceivedHttpResponse(HttpStatusCode.OK, headers, body)

    fun redirectUriAnswer(redirectUri: String) = jsonResponse(OpenId4VpSuccess(redirectUri))

    // Step sequences, see the KDoc of the methods of OpenId4VpProtocolClient

    test("authorization response is posted as form without charset") {
        val http = FakeHttpStack(scripted(plainAnswer("")))

        http.execute(client().sendAuthorizationResponse(response)).shouldBeNull()

        http.sent.kinds() shouldBe listOf("AuthorizationResponse")
        http.sent.single().http.apply {
            url shouldBe response.url
            method shouldBe HttpMethod.Post
            headers.getAll(HttpHeaders.ContentType) shouldBe listOf("application/x-www-form-urlencoded")
            formParameters() shouldBe response.params
        }
    }

    test("redirect_uri of the verifier's answer is returned for an absolute https URI on any host") {
        val redirectUris = listOf(
            "https://verifier.example.com/cb#response_code=091535f699ea575c7937fa5f0f454aee",
            "https://other.example.org:8443/session?id=a%20b",
            "HTTPS://verifier.example.com",
        )
        val http = FakeHttpStack(scripted(*redirectUris.map { redirectUriAnswer(it) }.toTypedArray()))

        redirectUris.forEach {
            http.execute(client().sendAuthorizationResponse(response)) shouldBe it
        }
    }

    test("no redirect_uri for an empty or non-JSON body, or JSON without redirect_uri") {
        val bodies = listOf("", "OK", "<html></html>", "{}", """{"redirect_uri":""}""", """{"status":"ok"}""")
        val http = FakeHttpStack(scripted(*bodies.map { plainAnswer(it) }.toTypedArray()))

        repeat(bodies.size) {
            http.execute(client().sendAuthorizationResponse(response)).shouldBeNull()
        }
    }

    test("redirect_uri that is not an absolute https URI fails") {
        val redirectUris = listOf(
            "javascript:alert(document.cookie)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "intent://cb#Intent;scheme=eudi;package=com.example.attacker;end",
            "eudi-wallet://cb?code=1",
            "http://verifier.example.com/cb",
            "/cb#response_code=1",
            "//verifier.example.com/cb",
            "https:///cb",
            "https:verifier.example.com/cb",
            " https://verifier.example.com/cb",
        )
        val http = FakeHttpStack(scripted(*redirectUris.map { redirectUriAnswer(it) }.toTypedArray()))

        redirectUris.forEach {
            shouldThrow<IllegalArgumentException> {
                http.execute(client().sendAuthorizationResponse(response))
            }.message shouldBe "redirect_uri of the verifier is not an absolute https URI: $it"
        }
        http.sent.kinds() shouldBe redirectUris.map { "AuthorizationResponse" }
    }

    test("Location header of the verifier's answer is ignored") {
        val location = headersOf(HttpHeaders.Location, "https://attacker.example.com/")
        val http = FakeHttpStack(
            scripted(
                plainAnswer("", location),
                jsonResponse(OpenId4VpSuccess("https://verifier.example.com/cb")) {
                    append(HttpHeaders.Location, "https://attacker.example.com/")
                },
            )
        )

        http.execute(client().sendAuthorizationResponse(response)).shouldBeNull()
        http.execute(client().sendAuthorizationResponse(response)) shouldBe "https://verifier.example.com/cb"
    }

    test("non-success answer fails, also for a redirect") {
        val redirect = ReceivedHttpResponse(
            status = HttpStatusCode.Found,
            headers = headersOf(HttpHeaders.Location, "https://verifier.example.com/cb"),
            body = "",
        )
        val http = FakeHttpStack(scripted(OAuth2Exception.InvalidRequest("unknown state").toErrorResponse(), redirect))

        shouldThrow<HttpErrorResponseException> {
            http.execute(client().sendAuthorizationResponse(response))
        }.apply {
            status shouldBe HttpStatusCode.BadRequest
            oauth2Error?.error shouldBe INVALID_REQUEST
        }
        shouldThrow<HttpErrorResponseException> {
            http.execute(client().sendAuthorizationResponse(response))
        }.status shouldBe HttpStatusCode.Found
        http.sent.kinds() shouldBe listOf("AuthorizationResponse", "AuthorizationResponse")
    }
}
