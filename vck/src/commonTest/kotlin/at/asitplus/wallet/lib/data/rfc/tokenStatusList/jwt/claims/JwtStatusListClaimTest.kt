package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt.claims

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class JwtStatusListClaimTest : FreeSpec({
    "specification robustness" {
        JwtStatusListClaim.Specification.CLAIM_NAME shouldBe "status_list"
    }
})