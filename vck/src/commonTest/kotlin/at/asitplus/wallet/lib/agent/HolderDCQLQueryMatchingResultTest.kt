package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryMatchingResult
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

val HolderDCQLQueryMatchingResultTest by matrixSuite {

    // One PID as SD-JWT or ISO mdoc, each with two alternative queries
    val dcqlQuery = Json.decodeFromString<DCQLQuery>(
        """
        {
          "credentials": [
            { "id": "sd-jwt-1", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } },
            { "id": "sd-jwt-2", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } },
            { "id": "mdoc-1", "format": "mso_mdoc", "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" } },
            { "id": "mdoc-2", "format": "mso_mdoc", "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" } }
          ],
          "credential_sets": [
            { "options": [ ["sd-jwt-1"], ["sd-jwt-2"], ["mdoc-1"], ["mdoc-2"] ] }
          ]
        }
        """.trimIndent()
    )

    // A PID as SD-JWT or ISO mdoc, and an optional loyalty card
    val withOptionalSet = Json.decodeFromString<DCQLQuery>(
        """
        {
          "credentials": [
            { "id": "pid-sd-jwt", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } },
            { "id": "pid-mdoc", "format": "mso_mdoc", "meta": { "doctype_value": "eu.europa.ec.eudi.pid.1" } },
            { "id": "loyalty", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:loyalty"] } }
          ],
          "credential_sets": [
            { "options": [ ["pid-sd-jwt"], ["pid-mdoc"] ] },
            { "required": false, "options": [ ["loyalty"] ] }
          ]
        }
        """.trimIndent()
    )

    /** Matches every credential to each query of [matchingQueries] of [dcql], and to no other query. */
    fun matching(
        credentials: List<String>,
        matchingQueries: Set<String>,
        dcql: DCQLQuery = dcqlQuery,
    ) = HolderDCQLQueryMatchingResult(
        dcqlQueryMatchingResult = DCQLQueryMatchingResult(
            dcql.credentials.associate { query ->
                query.id to credentials.map {
                    if (query.id.string in matchingQueries) {
                        KmmResult.success(DCQLCredentialQueryMatchingResult.AllClaimsMatchingResult)
                    } else {
                        KmmResult.failure(IllegalArgumentException("No match"))
                    }
                }
            }
        ),
        credentials = credentials,
    )

    "default submission skips options without matching credentials" {
        val submission = matching(listOf("mdoc"), setOf("mdoc-1", "mdoc-2"))
            .toDefaultSubmission(dcqlQuery).getOrThrow()

        submission.keys shouldBe setOf(DCQLCredentialQueryIdentifier("mdoc-1"))
        submission.values.single().map { it.credential } shouldBe listOf("mdoc")
    }

    "default submission fails if no option of a required credential set is satisfiable" {
        matching(listOf("mdoc"), setOf())
            .toDefaultSubmission(dcqlQuery).isFailure.shouldBeTrue()
    }

    "credential sets" - {
        test("each option tells whether the holder can satisfy it, optional sets included") {
            val matching = matching(listOf("mdoc", "card"), setOf("pid-mdoc", "loyalty"), withOptionalSet)

            val sets = matching.credentialSets(withOptionalSet)

            sets shouldBe listOf(
                HolderCredentialSet(
                    required = true,
                    options = listOf(
                        HolderCredentialSetOption(listOf(DCQLCredentialQueryIdentifier("pid-sd-jwt")), false),
                        HolderCredentialSetOption(listOf(DCQLCredentialQueryIdentifier("pid-mdoc")), true),
                    ),
                ),
                HolderCredentialSet(
                    required = false,
                    options = listOf(HolderCredentialSetOption(listOf(DCQLCredentialQueryIdentifier("loyalty")), true)),
                ),
            )
        }

        test("a query without credential sets is one required set of all its credential queries") {
            val query = Json.decodeFromString<DCQLQuery>(
                """
                {
                  "credentials": [
                    { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:eudi:pid:1"] } },
                    { "id": "loyalty", "format": "dc+sd-jwt", "meta": { "vct_values": ["urn:example:loyalty"] } }
                  ]
                }
                """.trimIndent()
            )
            val matching = matching(listOf("pid"), setOf("pid"), query)

            val sets = matching.credentialSets(query)

            sets shouldBe listOf(
                HolderCredentialSet(
                    required = true,
                    options = listOf(
                        HolderCredentialSetOption(
                            listOf(DCQLCredentialQueryIdentifier("pid"), DCQLCredentialQueryIdentifier("loyalty")),
                            false,
                        )
                    ),
                )
            )
        }
    }

    "submission of a selection" - {
        val matching = matching(listOf("mdoc", "card"), setOf("pid-mdoc", "loyalty"), withOptionalSet)

        test("presents the chosen option of an optional set") {
            val selection = listOf(1, 0)

            val submission = matching.toSubmission(withOptionalSet, selection).getOrThrow()

            submission.keys shouldBe
                    setOf(DCQLCredentialQueryIdentifier("pid-mdoc"), DCQLCredentialQueryIdentifier("loyalty"))
        }

        test("presents nothing for an optional set chosen with null") {
            val selection = listOf(1, null)

            val submission = matching.toSubmission(withOptionalSet, selection).getOrThrow()

            submission.keys shouldBe setOf(DCQLCredentialQueryIdentifier("pid-mdoc"))
        }

        "fails" - {
            listOf(
                listOf(null, 0) to "for no option of a required set",
                listOf(0, 0) to "for an option that can not be satisfied",
                listOf(2, 0) to "for an option that does not exist",
                listOf(1) to "without a choice for every set",
            ).forEach { (selection, name) ->
                test(name) {
                    val result = matching.toSubmission(withOptionalSet, selection)

                    result.isFailure.shouldBeTrue()
                }
            }
        }
    }
}
