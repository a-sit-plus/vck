package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe

val JwtSubjectClaimTest by testSuite {
    "specification robustness" {
        JwtSubjectClaim.Specification.CLAIM_NAME shouldBe "sub"
    }
}