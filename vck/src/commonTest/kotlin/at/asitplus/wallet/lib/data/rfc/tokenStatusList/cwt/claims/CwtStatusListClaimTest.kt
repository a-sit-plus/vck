package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class CwtStatusListClaimTest : FreeSpec({
    "specification robustness" {
        CwtStatusListClaim.Specification.CLAIM_NAME shouldBe "status_list"
        CwtStatusListClaim.Specification.CLAIM_KEY shouldBe 65533L
    }
})