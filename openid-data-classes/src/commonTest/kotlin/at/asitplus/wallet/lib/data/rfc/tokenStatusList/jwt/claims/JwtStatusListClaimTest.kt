package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val JwtStatusListClaimTest by testSuite {
    "specification robustness" {
        JwtStatusListClaim.Specification.CLAIM_NAME shouldBe "status_list"
    }
}