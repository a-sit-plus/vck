package at.asitplus.wallet.ios

import at.asitplus.signum.internals.toByteArray
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.HttpBody
import at.asitplus.wallet.lib.PreparedHttpRequest
import at.asitplus.wallet.lib.ProtocolRequest
import at.asitplus.wallet.lib.ReceivedHttpResponse
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import at.asitplus.wallet.lib.openid.OpenId4VpProtocolClient
import at.asitplus.wallet.lib.validation.HolderBindingPolicy
import at.asitplus.wallet.lib.validation.RegistrationPolicy
import at.asitplus.wallet.lib.validation.RelyingPartyTrustAnchors
import at.asitplus.wallet.lib.validation.RequiredClaimsPolicy
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes

private fun validationPolicy(timeLeewaySeconds: Double) = ValidationBridge.policy(
    TrustPolicy.IntegrityOnly, StatusPolicy.Skip, timeLeewaySeconds, true,
    HolderBindingPolicy.None, RequiredClaimsPolicy.Skip, RegistrationPolicy.Require,
)

val SwiftBridgeTest by matrixSuite {

    test("clock adapter exposes the system clock") {
        val clock = ClockAdapter.system

        clock shouldBeSameInstanceAs Clock.System
    }

    test("validation bridge takes time leeway in seconds") {
        val policy = validationPolicy(300.0)

        policy.timeLeeway shouldBe 5.minutes
        shouldThrow<IllegalArgumentException> { validationPolicy(-1.0) }
        shouldThrow<IllegalArgumentException> { validationPolicy(Double.NaN) }
    }

    test("validation bridge builds relying party validator with defaults") {
        val statusValidator = ValidationBridge.statusValidator(null, null, null)

        ValidationBridge.relyingPartyValidator(
            RelyingPartyTrustAnchors(),
            statusValidator,
            365.days.inWholeSeconds.toDouble(),
            null,
            null,
        )
    }

    test("HTTP exchange bridge flattens requests") {
        val request = ProtocolRequest.RequestObject(
            PreparedHttpRequest(
                url = "https://rp.example/request",
                method = HttpMethod.Post,
                headers = headersOf("Accept" to listOf("a", "b")),
                body = HttpBody(ContentType.Application.FormUrlEncoded, "x=1"),
            )
        )

        val flat = HttpExchangeBridge.request(request)

        flat.url shouldBe "https://rp.example/request"
        flat.method shouldBe "POST"
        flat.headers shouldBe mapOf("Accept" to "a, b")
        flat.contentType shouldBe "application/x-www-form-urlencoded"
        flat.body?.toByteArray()?.decodeToString() shouldBe "x=1"
    }

    test("HTTP exchange bridge builds responses") {
        val headers = mapOf("Location" to "https://rp.example/next")

        val response = HttpExchangeBridge.response(201, headers, "body")

        response.status shouldBe HttpStatusCode.Created
        response.headers["Location"] shouldBe "https://rp.example/next"
        response.body shouldBe "body"
    }

    test("exchanges run over a Swift transport") {
        val sent = mutableListOf<SwiftHttpRequest>()
        val transport = object : HttpTransport {
            override suspend fun send(request: SwiftHttpRequest): ReceivedHttpResponse {
                sent += request
                return HttpExchangeBridge.response(200, emptyMap(), """{"redirect_uri":"https://verifier.example/done"}""")
            }
        }
        val client = OpenId4VpProtocolClient(OpenId4VpHolderBuilder().build())

        val redirect = client.sendAuthorizationResponse(
            AuthenticationResponseResult.Post("https://verifier.example/response", mapOf("vp_token" to "token"))
        ).execute(transport)

        redirect shouldBe "https://verifier.example/done"
        sent.map { "${it.method} ${it.url}" } shouldBe listOf("POST https://verifier.example/response")
    }
}
