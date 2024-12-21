package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class JwtSubjectClaimTest : FreeSpec({
    "specification robustness" {
        JwtSubjectClaim.Specification.CLAIM_NAME shouldBe "sub"
    }
})