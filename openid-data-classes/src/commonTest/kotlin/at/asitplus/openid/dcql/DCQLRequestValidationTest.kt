package at.asitplus.openid.dcql

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

/** Requirements of OpenID4VP 1.0, 6, on the structure of a DCQL query. */
val DCQLRequestValidationTest by matrixSuite {

    fun query(credentials: String, credentialSets: String? = null) = Json.decodeFromString<DCQLQuery>(
        """{"credentials": $credentials${credentialSets?.let { """, "credential_sets": $it""" } ?: ""}}"""
    )

    val sdJwt = """{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}"""
    val mdoc = """{"id": "mdl", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}"""

    "a well-formed query is accepted" {
        shouldNotThrowAny {
            query(
                """[$sdJwt, "claims": [{"id": "a", "path": ["given_name"], "values": ["Erika"]}],
                    "claim_sets": [["a"]]}, $mdoc}]""",
                """[{"options": [["pid"], ["mdl"]]}]""",
            )
        }
    }

    "malformed queries are rejected" - {
        mapOf(
            "empty values of a JSON claim (6.3)" to """[$sdJwt, "claims": [{"path": ["given_name"], "values": []}]}]""",
            "empty values of an mdoc claim (6.3)" to
                    """[$mdoc, "claims": [{"path": ["ns", "given_name"], "values": [], "intent_to_retain": false}]}]""",
            "empty vct_values (B.3.5)" to """[{"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": []}}]""",
            "an empty array in type_values (B.1.1)" to
                    """[{"id": "vc", "format": "jwt_vc_json", "meta": {"type_values": [["VerifiableCredential"], []]}}]""",
            "claim_sets referencing an unknown claim (6.1)" to
                    """[$sdJwt, "claims": [{"id": "a", "path": ["given_name"]}], "claim_sets": [["a"], ["b"]]}]""",
        ).entries.asData(nameFn = { it.key }) test { (_, credentials) ->
            shouldThrowAny { query(credentials) }
        }
        mapOf(
            "an empty array in options (6.2)" to """[{"options": [["pid"], []]}]""",
            "options referencing an unknown Credential Query (6.2)" to """[{"options": [["pid"], ["unknown"]]}]""",
        ).entries.asData(nameFn = { it.key }) test { (_, credentialSets) ->
            shouldThrowAny { query("[$sdJwt}]", credentialSets) }
        }
    }

    "a claims query pointing to the same claim again is ignored (6.1)" {
        val credentialQuery = query(
            """[$sdJwt, "claims": [{"path": ["given_name"]}, {"path": ["family_name"]}, {"path": ["given_name"]}]}]"""
        ).credentials.single()

        val result = credentialQuery.matchClaimsQueriesAgainstClaimStructure(
            credentialStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {
                put("given_name", JsonPrimitive("Erika"))
                put("family_name", JsonPrimitive("Musterfrau"))
            }),
            satisfiesSelectiveDisclosure = true,
        ).getOrThrow()

        result.shouldBeInstanceOf<DCQLCredentialQueryMatchingResult.ClaimsQueryResults>()
            .claimsQueryResults.map {
                it.shouldBeInstanceOf<DCQLClaimsQueryResult.JsonResult>().nodeList.single().value
            } shouldBe listOf(JsonPrimitive("Erika"), JsonPrimitive("Musterfrau"))
    }
}
