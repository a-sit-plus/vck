package at.asitplus.wallet.lib.agent

import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.LibraryInitializer
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElement
import at.asitplus.wallet.lib.data.CredentialToJsonConverter.toJsonElementOrNull
import at.asitplus.wallet.lib.data.rfc3986.toUri
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Instant

/**
 * OpenID4VP 1.0, 6.3: the CBOR value of an ISO mdoc data element is converted to JSON before it is matched against the
 * `values` of a claims query.
 */
val DCQLIsoMdocValueMatchingTest by matrixSuite {

    "conversion to JSON for matching" - {
        "dates, date-times and byte strings are converted to their string" {
            LocalDate(1990, 1, 1).toJsonElementOrNull() shouldBe JsonPrimitive("1990-01-01")
            Instant.parse("2026-10-22T08:15:30Z").toJsonElementOrNull() shouldBe JsonPrimitive("2026-10-22T08:15:30Z")
            byteArrayOf(-5, -1).toJsonElementOrNull() shouldBe JsonPrimitive("-_8")
        }
        "a type with a registered encoder is converted by it" {
            LibraryInitializer.registerCredentialSerializers(
                jsonValueEncoder = { (it as? RegisteredCode)?.let { JsonPrimitive(it.code) } }
            )
            RegisteredCode(1).toJsonElementOrNull() shouldBe JsonPrimitive(1)
        }
        "a type without an encoding is not converted, instead of being represented by its string" {
            UnknownValue("1").toJsonElementOrNull().shouldBeNull()
            UnknownValue("1").toJsonElement() shouldBe JsonPrimitive("UnknownValue(value=1)")
        }
    }

    "values of a stored ISO mdoc" - {
        suspend fun matchesDateOfBirth(expected: String): Boolean {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holder = HolderAgent(keyMaterial = holderKeyMaterial)
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
            )
            // issued with date_of_birth 1990-01-01, a full-date (tag 1004)
            holder.storeCredential(issueIsoMdoc(issuer, holderKeyMaterial).toStoreCredentialInput()).getOrThrow()
            val query = Json.decodeFromString<DCQLQuery>(
                """
                {
                  "credentials": [{
                    "id": "mdoc",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "${AtomicAttribute2023.isoDocType}" },
                    "claims": [{
                      "path": ["${AtomicAttribute2023.isoNamespace}", "${AtomicAttribute2023.CLAIM_DATE_OF_BIRTH}"],
                      "values": ["$expected"]
                    }]
                  }]
                }
                """.trimIndent()
            )
            val matching = holder.matchPresentationRequestAgainstCredentialStore(
                CredentialPresentationRequest.DCQLRequest(query)
            ).getOrThrow().shouldBeInstanceOf<at.asitplus.wallet.lib.agent.DCQLMatchingResult<*>>()
            return matching.matchingResult.credentialQueryMatches.values.single().isNotEmpty()
        }

        "a full-date matches its string" {
            matchesDateOfBirth("1990-01-01") shouldBe true
        }
        "a full-date does not match another date" {
            matchesDateOfBirth("1990-01-02") shouldBe false
        }
    }
}

private data class RegisteredCode(val code: Int)

private data class UnknownValue(val value: String)
