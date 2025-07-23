package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

class JwtIssuedAtClaimTest : FreeSpec({
    "specification robustness" {
        JwtIssuedAtClaim.Specification.CLAIM_NAME shouldBe "iat"
    }
})