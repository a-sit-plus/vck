package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe

val CwtSubjectClaimTest by testSuite{
    "specification robustness" {
        CwtSubjectClaim.Specification.CLAIM_NAME shouldBe "sub"
        CwtSubjectClaim.Specification.CLAIM_KEY shouldBe 2L
    }
}