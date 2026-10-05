package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.AttestationChallengeResponse
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.PushedAuthenticationResponseParameters
import at.asitplus.openid.TokenIntrospectionJwtPayload
import at.asitplus.openid.TokenIntrospectionJwtResponse
import at.asitplus.openid.TokenIntrospectionResponse
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.openid.AuthenticationResponseResult
import io.kotest.matchers.shouldBe
import io.ktor.http.*
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

private const val NONCE = "server-nonce"
private const val CHALLENGE = "server-challenge"

val AuthorizationServerResponsesTest by matrixSuite {

    test("authorization server metadata") {
        val metadata = OAuth2AuthorizationServerMetadata(issuer = "https://as.example.com")

        metadata.toHttpResponse().apply {
            status shouldBe HttpStatusCode.OK
            headers.names() shouldBe setOf(HttpHeaders.ContentType)
            shouldBeJson()
            joseCompliantSerializer.decodeFromString<OAuth2AuthorizationServerMetadata>(body) shouldBe metadata
        }
    }

    test("attestation challenge is not cached") {
        val challenge = AttestationChallengeResponse(CHALLENGE)

        challenge.toHttpResponse().apply {
            status shouldBe HttpStatusCode.OK
            shouldBeJson()
            headers[HttpHeaders.CacheControl] shouldBe "no-store"
            joseCompliantSerializer.decodeFromString<AttestationChallengeResponse>(body) shouldBe challenge
        }
    }

    testSuite("pushed authorization response") {
        val par = PushedAuthenticationResponseParameters(requestUri = "urn:ietf:params:oauth:request_uri:1", 5.minutes)

        test("is created, with fresh DPoP nonce and attestation challenge") {
            ResponseWithDpopNonce(par, NONCE, CHALLENGE).toHttpResponse().apply {
                status shouldBe HttpStatusCode.Created
                shouldBeJson()
                headers[HttpHeaders.DPoPNonce] shouldBe NONCE
                headers[HttpHeaders.OAuthClientAttestationChallenge] shouldBe CHALLENGE
                joseCompliantSerializer.decodeFromString<PushedAuthenticationResponseParameters>(body) shouldBe par
            }
        }

        test("without DPoP nonce and attestation challenge") {
            ResponseWithDpopNonce(par, null).toHttpResponse().headers.names() shouldBe setOf(HttpHeaders.ContentType)
        }
    }

    test("authorization redirects to the client") {
        val url = "https://client.example.com/cb?code=abc&state=xyz"

        AuthenticationResponseResult.Redirect(url).toHttpResponse() shouldBe PreparedHttpResponse(
            status = HttpStatusCode.Found,
            headers = headersOf(HttpHeaders.Location, url),
        )
    }

    testSuite("token response") {
        val token = TokenResponseParameters(accessToken = "access-token", tokenType = "DPoP")

        test("is not cached, with fresh DPoP nonce and attestation challenge") {
            ResponseWithDpopNonce(token, NONCE, CHALLENGE).toHttpResponse().apply {
                status shouldBe HttpStatusCode.OK
                shouldBeJson()
                headers[HttpHeaders.CacheControl] shouldBe "no-store"
                headers[HttpHeaders.Pragma] shouldBe "no-cache"
                headers[HttpHeaders.DPoPNonce] shouldBe NONCE
                headers[HttpHeaders.OAuthClientAttestationChallenge] shouldBe CHALLENGE
                joseCompliantSerializer.decodeFromString<TokenResponseParameters>(body) shouldBe token
            }
        }

        test("without DPoP nonce and attestation challenge") {
            ResponseWithDpopNonce(token, null).toHttpResponse().headers.names() shouldBe
                    setOf(HttpHeaders.ContentType, HttpHeaders.CacheControl, HttpHeaders.Pragma)
        }
    }

    testSuite("token introspection") {
        test("plain response") {
            val introspection = TokenIntrospectionResponse(active = true, scope = "openid")

            introspection.toHttpResponse().apply {
                status shouldBe HttpStatusCode.OK
                shouldBeJson()
                joseCompliantSerializer.decodeFromString<TokenIntrospectionResponse>(body) shouldBe introspection
            }
        }

        test("JWT response as application/token-introspection+jwt") {
            val jwt = SignJwt<TokenIntrospectionJwtPayload>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
                JwsContentTypeConstants.TOKEN_INTROSPECTION_JWT,
                TokenIntrospectionJwtPayload(
                    issuer = "https://as.example.com",
                    audience = "https://rs.example.com",
                    issuedAt = Clock.System.now(),
                    tokenIntrospection = TokenIntrospectionResponse(active = true),
                ),
                TokenIntrospectionJwtPayload.serializer(),
            ).getOrThrow()

            TokenIntrospectionJwtResponse(jwt).toHttpResponse().apply {
                status shouldBe HttpStatusCode.OK
                headers.names() shouldBe setOf(HttpHeaders.ContentType)
                headers[HttpHeaders.ContentType] shouldBe "application/token-introspection+jwt"
                body shouldBe jwt.jws.toString()
            }
        }
    }

    test("userinfo with fresh DPoP nonce") {
        val userInfo = buildJsonObject { put("sub", JsonPrimitive("user")) }

        ResponseWithDpopNonce(userInfo, NONCE).toHttpResponse().apply {
            status shouldBe HttpStatusCode.OK
            shouldBeJson()
            headers[HttpHeaders.DPoPNonce] shouldBe NONCE
            headers[HttpHeaders.CacheControl] shouldBe null
            body shouldBe """{"sub":"user"}"""
        }
    }
}

private fun PreparedHttpResponse.shouldBeJson() {
    headers[HttpHeaders.ContentType] shouldBe ContentType.Application.Json.toString()
}
