package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class CwtIssuedAtClaimTest : FreeSpec({
    "specification robustness" {
        CwtIssuedAtClaim.Specification.CLAIM_NAME shouldBe "iat"
        CwtIssuedAtClaim.Specification.CLAIM_KEY shouldBe 6L
    }
})