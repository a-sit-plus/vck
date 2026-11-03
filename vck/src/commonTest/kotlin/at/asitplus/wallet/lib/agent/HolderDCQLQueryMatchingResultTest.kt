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

    /** Matches every credential to each query of [matchingQueries], and to no other query. */
    fun matching(credentials: List<String>, matchingQueries: Set<String>) = HolderDCQLQueryMatchingResult(
        dcqlQueryMatchingResult = DCQLQueryMatchingResult(
            dcqlQuery.credentials.associate { query ->
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
}
