package at.asitplus.openid.dcql

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

val DCQLCredentialQueryTest by matrixSuite {
    "specification" - {
        "serial names" {
            DCQLCredentialQuery.SerialNames.ID shouldBe "id"
            DCQLCredentialQuery.SerialNames.FORMAT shouldBe "format"
            DCQLCredentialQuery.SerialNames.META shouldBe "meta"
            DCQLCredentialQuery.SerialNames.CLAIM_SETS shouldBe "claim_sets"
            DCQLCredentialQuery.SerialNames.CLAIMS shouldBe "claims"
        }
    }
    "claims matching" - {
        val query = DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier("query"),
            format = CredentialFormatEnum.DC_SD_JWT,
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf("vct")),
        )
        val claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {
            put("family_name", JsonPrimitive("Musterfrau"))
        })

        "absent claims request only mandatory claims for selectively disclosable credentials" {
            query.matchClaimsQueriesAgainstClaimStructure(
                credentialStructure = claimStructure,
                satisfiesSelectiveDisclosure = true,
            ).getOrThrow() shouldBe DCQLCredentialQueryMatchingResult.AllMandatoryClaimsMatchingResult
        }
        "absent claims request all claims for non-selectively disclosable credentials" {
            query.matchClaimsQueriesAgainstClaimStructure(
                credentialStructure = claimStructure,
                satisfiesSelectiveDisclosure = false,
            ).getOrThrow() shouldBe DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult
        }
        "present claims request exactly the listed claims" {
            val result = query.copy(
                claims = DCQLClaimsQueryList(
                    DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer("family_name"))
                )
            ).matchClaimsQueriesAgainstClaimStructure(
                credentialStructure = claimStructure,
                satisfiesSelectiveDisclosure = true,
            ).getOrThrow()

            result.shouldBeInstanceOf<DCQLCredentialQueryMatchingResult.ClaimsQueryResults>()
                .claimsQueryResults.single()
                .shouldBeInstanceOf<DCQLClaimsQueryResult.JsonResult>()
                .nodeList.single().value shouldBe JsonPrimitive("Musterfrau")
        }
    }
    "claim sets (OpenID4VP 1.0, 7.1.1 and 6.4.1)" - {
        val query = DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier("query"),
            format = CredentialFormatEnum.DC_SD_JWT,
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(vctValues = listOf("vct")),
            claims = DCQLClaimsQueryList(
                DCQLJsonClaimsQuery(
                    id = DCQLClaimsQueryIdentifier("wrong_type"),
                    path = DCQLClaimsPathPointer("mixed") + null + "x",
                ),
                DCQLJsonClaimsQuery(
                    id = DCQLClaimsQueryIdentifier("present"),
                    path = DCQLClaimsPathPointer("family_name"),
                ),
            ),
        )
        val claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {
            put("family_name", JsonPrimitive("Musterfrau"))
            put("mixed", buildJsonArray {
                add(buildJsonObject { put("x", JsonPrimitive("yes")) })
                add(JsonPrimitive("text"))
            })
        })

        "a claim whose path selects an element of the wrong type does not match" {
            query.matchClaimsQueriesAgainstClaimStructure(
                credentialStructure = claimStructure,
                satisfiesSelectiveDisclosure = true,
            ).isFailure shouldBe true
        }
        "another option of claim_sets without that claim still matches" {
            val result = query.copy(
                claimSets = nonEmptyListOf(
                    nonEmptyListOf(DCQLClaimsQueryIdentifier("wrong_type")),
                    nonEmptyListOf(DCQLClaimsQueryIdentifier("present")),
                )
            ).matchClaimsQueriesAgainstClaimStructure(
                credentialStructure = claimStructure,
                satisfiesSelectiveDisclosure = true,
            ).getOrThrow()

            result.shouldBeInstanceOf<DCQLCredentialQueryMatchingResult.ClaimsQueryResults>()
                .claimsQueryResults.single()
                .shouldBeInstanceOf<DCQLClaimsQueryResult.JsonResult>()
                .nodeList.single().value shouldBe JsonPrimitive("Musterfrau")
        }
    }
    "serialization" {
        val value = DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(
                Random.nextBytes(32).encodeToString(Base64UrlStrict)
            ),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(null)
                )
            ),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("mustmatch")
            )
        )

        val expectedJsonObject = buildJsonObject {
            put(DCQLCredentialQuery.SerialNames.ID, JsonPrimitive(value.id.string))
            put(
                DCQLCredentialQuery.SerialNames.FORMAT,
                JsonPrimitive(CredentialFormatEnum.DC_SD_JWT.text)
            )
            put(
                DCQLCredentialQuery.SerialNames.META,
                buildJsonObject {
                    put(
                        DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES,
                        buildJsonArray {
                            add("mustmatch")
                        }
                    )
                }
            )
            put(DCQLCredentialQuery.SerialNames.CLAIMS, buildJsonArray {
                add(buildJsonObject {
                    put(DCQLClaimsQuery.SerialNames.PATH, buildJsonArray {
                        add(JsonNull)
                    })
                })
            })
        }

        Json.encodeToJsonElement(value) shouldBe expectedJsonObject.also {
            println(it)
        }
        Json.decodeFromJsonElement<DCQLCredentialQuery>(expectedJsonObject) shouldBe value
    }
}
