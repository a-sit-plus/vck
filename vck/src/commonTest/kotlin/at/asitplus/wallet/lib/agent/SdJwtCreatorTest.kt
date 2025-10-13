package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SdJwtConstants
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.jsonArray

class SdJwtCreatorTest : FreeSpec({

    "name can be selectively disclosed" {
        listOfClaims("name").toSdJsonObject(RandomSource.Default).apply {
            second.shouldHaveSize(1)
            first["_sd"]!!.jsonArray shouldHaveSize 1
            first["_sd_alg"] shouldBe SdJwtConstants.SHA_256.toJsonElement()
            first["name"] shouldBe null
        }
    }

    "digest can be specified" {
        listOfClaims("name").toSdJsonObject(RandomSource.Default, Digest.SHA384).apply {
            second.shouldHaveSize(1)
            first["_sd"]!!.jsonArray shouldHaveSize 1
            first["_sd_alg"] shouldBe SdJwtConstants.SHA_384.toJsonElement()
            first["name"] shouldBe null
        }
    }

    "issuer MUST be included in SD-JWT, i.e. can not be selectively disclosed" {
        listOfClaims("name", "iss").toSdJsonObject(RandomSource.Default).apply {
            second.shouldHaveSize(1)
            first["_sd"]!!.jsonArray shouldHaveSize 1
            first["name"] shouldBe null
            first["iss"] shouldNotBe null
        }
    }

    "nbf, cnf, vct, status MUST be included in SD-JWT, i.e. can not be selectively disclosed" {
        listOfClaims("nbf", "cnf", "vct", "status").toSdJsonObject(RandomSource.Default).apply {
            second.shouldHaveSize(0)
            first["_sd"] shouldBe null
            first["nbf"] shouldNotBe null
            first["cnf"] shouldNotBe null
            first["vct"] shouldNotBe null
            first["status"] shouldNotBe null
        }
    }

    "several names are disallowed" {
        listOfClaims("_sd_alg", "...").toSdJsonObject(RandomSource.Default).apply {
            second.shouldHaveSize(0)
            first["_sd"] shouldBe null
            first["..."] shouldBe null
        }
    }

})

private fun listOfClaims(vararg claimName: String): List<ClaimToBeIssued> =
    claimName.map { ClaimToBeIssued(it, uuid4(), true) }