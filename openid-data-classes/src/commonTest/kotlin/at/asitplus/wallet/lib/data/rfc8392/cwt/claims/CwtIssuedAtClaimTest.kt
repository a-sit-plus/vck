package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val CwtIssuedAtClaimTest by testSuite {
    "specification robustness" {
        CwtIssuedAtClaim.Specification.CLAIM_NAME shouldBe "iat"
        CwtIssuedAtClaim.Specification.CLAIM_KEY shouldBe 6L
    }
}