package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.jsonArray

class SdJwtCreatorTest : FreeSpec({

    "name can be selectively disclosed" {
        listOfClaims("name").toSdJsonObject().apply {
            second.shouldHaveSize(1)
            first["_sd"]!!.jsonArray shouldHaveSize 1
            first["name"] shouldBe null
        }
    }

    "issuer MUST be included in SD-JWT, i.e. can not be selectively disclosed" {
        listOfClaims("name", "iss").toSdJsonObject().apply {
            second.shouldHaveSize(1)
            first["_sd"]!!.jsonArray shouldHaveSize 1
            first["name"] shouldBe null
            first["iss"] shouldNotBe null
        }
    }

    "nbf, cnf, vct, status MUST be included in SD-JWT, i.e. can not be selectively disclosed" {
        listOfClaims("nbf", "cnf", "vct", "status").toSdJsonObject().apply {
            second.shouldHaveSize(0)
            first["_sd"] shouldBe null
            first["nbf"] shouldNotBe null
            first["cnf"] shouldNotBe null
            first["vct"] shouldNotBe null
            first["status"] shouldNotBe null
        }
    }

})

private fun listOfClaims(vararg claimName: String): List<ClaimToBeIssued> =
    claimName.map { ClaimToBeIssued(it, uuid4(), true) }