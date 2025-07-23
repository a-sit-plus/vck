package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.test.FreeSpec
import io.kotest.matchers.shouldBe

class CwtIssuedAtClaimTest : FreeSpec({
    "specification robustness" {
        CwtIssuedAtClaim.Specification.CLAIM_NAME shouldBe "iat"
        CwtIssuedAtClaim.Specification.CLAIM_KEY shouldBe 6L
    }
})