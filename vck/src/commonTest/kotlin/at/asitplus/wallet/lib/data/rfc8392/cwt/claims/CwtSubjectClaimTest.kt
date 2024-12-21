package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class CwtSubjectClaimTest : FreeSpec({
    "specification robustness" {
        CwtSubjectClaim.Specification.CLAIM_NAME shouldBe "sub"
        CwtSubjectClaim.Specification.CLAIM_KEY shouldBe 2L
    }
})