package at.asitplus.wallet.lib.agent

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.ClaimsQueryResults
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import com.benasher44.uuid.uuid4
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * A holder matches DCQL claims queries on the claims of [SdJwtDecoded] and presents the disclosures at the selected
 * positions, so both count array elements alike, also next to decoy digests (RFC 9901, 4.2.5), empty objects (7.1 step
 * 3.e), and in nested arrays (7.1 step 3.c.iii.3).
 */
val SdJwtDcqlDisclosureTest by matrixSuite {

    "the holder's DCQL view of an SD-JWT is its decoded claims, without _sd and _sd_alg" {
        val example = sdJwtDecodedExample()
        CredentialToJsonConverter.toJsonElement(example.storeEntry()) shouldBe example.decoded.reconstructedJsonObject
    }

    listOf(
        PresentationCase("an array element after a decoy", query(pointer("nationalities", 1)), "nat", "fr"),
        PresentationCase("all array elements", query(pointer("nationalities", null)), "nat", "de", "fr"),
        PresentationCase("an array element by value", query(pointer("nationalities", null), "FR"), "nat", "fr"),
        PresentationCase("a claim with its sub-claims", query(pointer("degrees")), "deg", "u0", "d1", "u1"),
        PresentationCase("a nested claim", query(pointer("degrees", 1, "university")), "deg", "d1", "u1"),
        PresentationCase("an element after an empty object", query(pointer("e", null), "E1"), "e1"),
        PresentationCase("an element of a nested array", query(pointer("m", 0, null), "Y"), "y"),
    ).forEach { case ->
        "presents ${case.name} with its ancestors and sub-claims only" {
            val example = sdJwtDecodedExample()
            val credential = example.storeEntry()
            val selected = case.query.executeClaimsQueryAgainstCredential(
                DCQLCredentialClaimStructure.JsonBasedStructure(CredentialToJsonConverter.toJsonElement(credential))
            ).getOrThrow()

            VerifiablePresentationFactory(EphemeralKeyWithoutCert()).createVerifiablePresentation(
                request = PresentationRequestParameters(
                    nonce = uuid4().toString(),
                    audience = "https://verifier.example.org",
                ),
                credential = credential,
                disclosedAttributes = ClaimsQueryResults(listOf(selected)),
            ).getOrThrow().shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
                .sdJwt.rawDisclosures.toSet() shouldBe case.expected.map { example[it] }.toSet()
        }
    }
}

private class PresentationCase(val name: String, val query: DCQLJsonClaimsQuery, vararg val expected: String)

private fun query(path: DCQLClaimsPathPointer, vararg values: String) = DCQLJsonClaimsQuery(
    path = path,
    values = values.takeIf { it.isNotEmpty() }?.map { DCQLExpectedClaimValue.StringValue(it) },
)

private fun SdJwtDecodedExample.storeEntry() =
    SubjectCredentialStore.StoreEntry.SdJwt.fromString(serialized).getOrThrow()
