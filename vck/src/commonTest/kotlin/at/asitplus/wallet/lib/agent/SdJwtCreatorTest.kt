package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SdJwtConstants
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

val SdJwtCreatorTest by testSuite {

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

    "nested structures with sd elements are added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), true)), false)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(2)
            first["nested"].shouldNotBeNull().jsonObject["_sd"] shouldNotBe null
        }
    }

    "nested structures with elements are added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), false)), false)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(1)
            first["nested"].shouldNotBeNull().jsonObject["_sd"] shouldBe null
        }
    }

    "nested sd structures with inner sd elements are not added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), true)), true)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(3)
            first["nested"] shouldBe null
        }
    }

    "nested sd structures with inner elements are not added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), false)), true)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(2)
            first["nested"] shouldBe null
        }
    }

    "array not selectively disclosable, but elements within" {
        listOf(
            ClaimToBeIssued("array", listOf(
                ClaimToBeIssuedArrayElement("1", true),
                ClaimToBeIssuedArrayElement("2", false)
            ), false)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(1)
            first["array"].shouldNotBeNull().jsonArray.apply {
                shouldHaveSize(2)
                first() shouldBe JsonPrimitive("1")
                get(1).jsonObject.shouldNotBeNull().apply {
                    shouldHaveSize(1)
                    get("...").shouldNotBeNull()
                }
            }
        }
    }

    "array selectively disclosable, and elements within too" {
        listOf(
            ClaimToBeIssued("array", listOf(
                ClaimToBeIssuedArrayElement("1", true),
                ClaimToBeIssuedArrayElement("2", true)
            ), true)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(3)
            first["array"] shouldBe null
        }
    }

}

private fun listOfClaims(vararg claimName: String): List<ClaimToBeIssued> =
    claimName.map { ClaimToBeIssued(it, uuid4(), true) }