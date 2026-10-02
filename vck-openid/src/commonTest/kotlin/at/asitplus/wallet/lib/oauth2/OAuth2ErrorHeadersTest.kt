package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.Errors.USE_ATTESTATION_CHALLENGE
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import com.benasher44.uuid.uuid4
import io.kotest.matchers.shouldBe
import io.ktor.http.*

val OAuth2ErrorHeadersTest by matrixSuite {

    test("dpopNonce reads the nonce of an authorization server error use_dpop_nonce") {
        val nonce = uuid4().toString()
        val headers = headersOf(HttpHeaders.DPoPNonce, nonce)

        OAuth2Error(error = USE_DPOP_NONCE).dpopNonce(headers) shouldBe nonce
        OAuth2Error(error = "invalid_request").dpopNonce(headers) shouldBe null
    }

    test("dpopNonce reads the nonce of a resource server challenge in WWW-Authenticate") {
        val nonce = uuid4().toString()
        val headers = headers {
            append(HttpHeaders.WWWAuthenticate, "DPoP error=\"$USE_DPOP_NONCE\"")
            append(HttpHeaders.DPoPNonce, nonce)
        }

        null.dpopNonce(headers) shouldBe nonce
        null.dpopNonce(headersOf(HttpHeaders.DPoPNonce, nonce)) shouldBe null
    }

    test("attestationChallenge reads the challenge of the error use_attestation_challenge") {
        val challenge = uuid4().toString()
        val headers = headersOf(HttpHeaders.OAuthClientAttestationChallenge, challenge)

        OAuth2Error(error = USE_ATTESTATION_CHALLENGE).attestationChallenge(headers) shouldBe challenge
        OAuth2Error(error = USE_DPOP_NONCE).attestationChallenge(headers) shouldBe null
        null.attestationChallenge(headers) shouldBe null
    }
}
