package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.SdJwtCreator.toSdJsonObject
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.SdJwtConstants
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
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
            signDecodeReconstruct().apply {
                this["outer"].shouldBeInstanceOf<JsonPrimitive>()
                this["nested"].shouldBeInstanceOf<JsonObject>().apply {
                    entries.shouldHaveSize(1)
                    this["inner"].shouldBeInstanceOf<JsonPrimitive>()
                }
            }
        }
    }

    "nested structures with elements are added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), false)), false)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(1)
            first["nested"].shouldNotBeNull().jsonObject["_sd"] shouldBe null
            signDecodeReconstruct().apply {
                this["outer"].shouldBeInstanceOf<JsonPrimitive>()
                this["nested"].shouldBeInstanceOf<JsonObject>().apply {
                    entries.shouldHaveSize(1)
                    this["inner"].shouldBeInstanceOf<JsonPrimitive>()
                }
            }
        }
    }

    "nested sd structures with inner sd elements are not added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), true)), true)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(3)
            first["nested"] shouldBe null
            signDecodeReconstruct().apply {
                this["outer"].shouldBeInstanceOf<JsonPrimitive>()
                this["nested"].shouldBeInstanceOf<JsonObject>().apply {
                    entries.shouldHaveSize(1)
                    this["inner"].shouldBeInstanceOf<JsonPrimitive>()
                }
            }
        }
    }

    "nested sd structures with inner elements are not added to the top level" {
        listOf(
            ClaimToBeIssued("outer", uuid4(), true),
            ClaimToBeIssued("nested", listOf(ClaimToBeIssued("inner", uuid4(), false)), true)
        ).toSdJsonObject().apply {
            second.shouldHaveSize(2)
            first["nested"] shouldBe null
            signDecodeReconstruct().apply {
                this["outer"].shouldBeInstanceOf<JsonPrimitive>()
                this["nested"].shouldBeInstanceOf<JsonObject>().apply {
                    entries.shouldHaveSize(1)
                    this["inner"].shouldBeInstanceOf<JsonPrimitive>()
                }
            }
        }
    }

    "array not selectively disclosable, but elements within" {
        listOf(
            ClaimToBeIssued(
                "array", listOf(
                    ClaimToBeIssuedArrayElement("1", false),
                    ClaimToBeIssuedArrayElement("2", true)
                ), false
            )
        ).toSdJsonObject().apply {
            second.shouldHaveSize(1)
            first["array"].shouldBeInstanceOf<JsonArray>().apply {
                shouldHaveSize(2)
                first() shouldBe JsonPrimitive("1")
                get(1).shouldBeInstanceOf<JsonObject>().apply {
                    entries.shouldBeSingleton()
                    get("...").shouldNotBeNull()
                }
            }
            signDecodeReconstruct().apply {
                this["array"].shouldBeInstanceOf<JsonArray>().apply {
                    shouldHaveSize(2)
                    get(0) shouldBe JsonPrimitive("1")
                    get(1) shouldBe JsonPrimitive("2")
                }
            }
        }
    }

    test("array selectively disclosable, and elements within too") {
        listOf(
            ClaimToBeIssued(
                "array", listOf(
                    ClaimToBeIssuedArrayElement("1", true),
                    ClaimToBeIssuedArrayElement("2", true)
                ), true
            )
        ).toSdJsonObject().apply {
            second.shouldHaveSize(3)
            first["array"] shouldBe null

            signDecodeReconstruct().apply {
                this["array"].shouldBeInstanceOf<JsonArray>().apply {
                    shouldHaveSize(2)
                    get(0) shouldBe JsonPrimitive("1")
                    get(1) shouldBe JsonPrimitive("2")
                }
            }
        }
    }

}

private suspend fun Pair<JsonObject, Collection<String>>.signDecodeReconstruct() = SdJwtDecoded(
    SdJwtSigned.issued(
        SignJwt<JsonObject>(EphemeralKeyWithoutCert(), JwsHeaderNone())(
            JwsContentTypeConstants.SD_JWT,
            payload = first,
            serializer = JsonObject.serializer()
        ).getOrThrow(), second.toList()
    )
).reconstructedJsonObject.shouldNotBeNull()

private fun listOfClaims(vararg claimName: String): List<ClaimToBeIssued> =
    claimName.map { ClaimToBeIssued(it, uuid4(), true) }