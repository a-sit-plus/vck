package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe

val CwtStatusListClaimTest by testSuite {
    "specification robustness" {
        CwtStatusListClaim.Specification.CLAIM_NAME shouldBe "status_list"
        CwtStatusListClaim.Specification.CLAIM_KEY shouldBe 65533L
    }
}