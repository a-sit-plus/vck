package at.asitplus.wallet.lib.oauth2

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import at.asitplus.wallet.lib.oidvci.OAuth2Exception
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.ktor.http.*

private const val NONCE = "server-nonce"
private const val CHALLENGE = "server-challenge"
private const val DESCRIPTION = "access token secret-token is invalid"

private data class ErrorCase(
    val name: String,
    val exception: OAuth2Exception,
    val response: PreparedHttpResponse,
    val status: HttpStatusCode,
    val wwwAuthenticate: String? = null,
    val dpopNonce: String? = null,
    val attestationChallenge: String? = null,
)

val OAuth2ErrorResponsesTest by matrixSuite {

    testSuite("error responses") {
        listOf(
            OAuth2Exception.InvalidRequest(DESCRIPTION).let {
                ErrorCase("AS invalid_request", it, it.toHttpResponse(), HttpStatusCode.BadRequest)
            },
            OAuth2Exception.InvalidClient(DESCRIPTION).let {
                ErrorCase("AS invalid_client", it, it.toHttpResponse(), HttpStatusCode.BadRequest)
            },
            OAuth2Exception.InvalidToken(DESCRIPTION).let {
                ErrorCase("AS invalid_token", it, it.toHttpResponse(), HttpStatusCode.BadRequest)
            },
            OAuth2Exception.UseDpopNonce(NONCE, DESCRIPTION).let {
                ErrorCase(
                    "AS use_dpop_nonce", it, it.toHttpResponse(), HttpStatusCode.BadRequest,
                    dpopNonce = NONCE,
                )
            },
            OAuth2Exception.UseAttestationChallenge(CHALLENGE, DESCRIPTION).let {
                ErrorCase(
                    "AS use_attestation_challenge", it, it.toHttpResponse(), HttpStatusCode.BadRequest,
                    attestationChallenge = CHALLENGE,
                )
            },
            OAuth2Exception.InvalidToken(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_token with Bearer token", it, it.toResourceServerHttpResponse("Bearer token"),
                    HttpStatusCode.Unauthorized, wwwAuthenticate = "Bearer error=\"invalid_token\"",
                )
            },
            OAuth2Exception.InvalidToken(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_token with DPoP token", it, it.toResourceServerHttpResponse("DPoP token"),
                    HttpStatusCode.Unauthorized, wwwAuthenticate = "DPoP error=\"invalid_token\"",
                )
            },
            OAuth2Exception.InvalidToken(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_token with lower-case dpop token", it, it.toResourceServerHttpResponse("dpop token"),
                    HttpStatusCode.Unauthorized, wwwAuthenticate = "DPoP error=\"invalid_token\"",
                )
            },
            OAuth2Exception.InvalidToken(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_token without Authorization", it, it.toResourceServerHttpResponse(null),
                    HttpStatusCode.Unauthorized, wwwAuthenticate = "Bearer error=\"invalid_token\"",
                )
            },
            OAuth2Exception.InvalidDpopProof(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_dpop_proof with Bearer token", it, it.toResourceServerHttpResponse("Bearer token"),
                    HttpStatusCode.Unauthorized, wwwAuthenticate = "DPoP error=\"invalid_dpop_proof\"",
                )
            },
            OAuth2Exception.UseDpopNonce(NONCE, DESCRIPTION).let {
                ErrorCase(
                    "RS use_dpop_nonce without Authorization", it, it.toResourceServerHttpResponse(null),
                    HttpStatusCode.Unauthorized, wwwAuthenticate = "DPoP error=\"use_dpop_nonce\"", dpopNonce = NONCE,
                )
            },
            OAuth2Exception.UseAttestationChallenge(CHALLENGE, DESCRIPTION).let {
                ErrorCase(
                    "RS use_attestation_challenge", it, it.toResourceServerHttpResponse("DPoP token"),
                    HttpStatusCode.BadRequest, attestationChallenge = CHALLENGE,
                )
            },
            OAuth2Exception.InvalidCredentialRequest(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_credential_request", it, it.toResourceServerHttpResponse("DPoP token"),
                    HttpStatusCode.BadRequest,
                )
            },
            OAuth2Exception.InvalidProof(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_proof", it, it.toResourceServerHttpResponse("DPoP token"),
                    HttpStatusCode.BadRequest,
                )
            },
            OAuth2Exception.InvalidNonce(DESCRIPTION).let {
                ErrorCase(
                    "RS invalid_nonce", it, it.toResourceServerHttpResponse("DPoP token"),
                    HttpStatusCode.BadRequest,
                )
            },
        ).asData(nameFn = { it.name }) test { case ->
            with(case.response) {
                status shouldBe case.status
                headers[HttpHeaders.ContentType] shouldBe ContentType.Application.Json.toString()
                headers[HttpHeaders.WWWAuthenticate] shouldBe case.wwwAuthenticate
                headers[HttpHeaders.DPoPNonce] shouldBe case.dpopNonce
                headers[HttpHeaders.OAuthClientAttestationChallenge] shouldBe case.attestationChallenge
                headers.names().forEach { name ->
                    headers.getAll(name).orEmpty().forEach { it shouldNotContain "secret-token" }
                }
                oauth2Error() shouldBe case.exception.toOAuth2Error()
            }
        }
    }

    testSuite("header-based client helpers read converted responses") {
        test("DPoP nonce of the authorization server") {
            val response = OAuth2Exception.UseDpopNonce(NONCE).toHttpResponse()

            response.oauth2Error().dpopNonce(response.headers) shouldBe NONCE
        }

        test("DPoP nonce of the resource server") {
            val response = OAuth2Exception.UseDpopNonce(NONCE).toResourceServerHttpResponse("DPoP token")

            response.oauth2Error().dpopNonce(response.headers) shouldBe NONCE
            null.dpopNonce(response.headers) shouldBe NONCE
        }

        test("attestation challenge of the authorization server") {
            val response = OAuth2Exception.UseAttestationChallenge(CHALLENGE).toHttpResponse()

            response.oauth2Error().attestationChallenge(response.headers) shouldBe CHALLENGE
        }
    }
}

private fun PreparedHttpResponse.oauth2Error() = joseCompliantSerializer.decodeFromString<OAuth2Error>(body)
