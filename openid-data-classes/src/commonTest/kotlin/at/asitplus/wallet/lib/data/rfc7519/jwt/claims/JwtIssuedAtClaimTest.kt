package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val JwtIssuedAtClaimTest by testSuite {
    "specification robustness" {
        JwtIssuedAtClaim.Specification.CLAIM_NAME shouldBe "iat"
    }
}