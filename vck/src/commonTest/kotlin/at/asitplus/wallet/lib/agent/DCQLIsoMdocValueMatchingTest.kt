package at.asitplus.wallet.lib.agent

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLExpectedClaimValue
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueIsoMdoc
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.procedures.dcql.toDcqlClaimValue
import at.asitplus.wallet.lib.procedures.dcql.toRfc8949Json
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborObject

/**
 * OpenID4VP 1.0, 6.3: the CBOR value of an ISO mdoc data element is converted to JSON, following RFC 8949, 6.1, before
 * it is matched against the `values` of a claims query.
 */
@OptIn(ExperimentalStdlibApi::class)
val DCQLIsoMdocValueMatchingTest by matrixSuite {

    "conversion of CBOR items to JSON (RFC 8949, 6.1)" - {
        mapOf(
            "unsigned integer" to ("01" to "1"),
            "negative integer" to ("21" to "-2"),
            "largest unsigned integer" to ("1bffffffffffffffff" to "18446744073709551615"),
            "smallest negative integer" to ("3bffffffffffffffff" to "-18446744073709551616"),
            "byte string as base64url" to ("420102" to "\"AQI\""),
            "indefinite byte string" to ("5f42010243030405ff" to "\"AQIDBAU\""),
            "text string" to ("626174" to "\"at\""),
            "indefinite text string" to ("7f61786179ff" to "\"xy\""),
            "false" to ("f4" to "false"),
            "true" to ("f5" to "true"),
            "null" to ("f6" to "null"),
            "undefined" to ("f7" to "null"),
            "floating-point number" to ("f93e00" to "1.5"),
            "NaN" to ("f97e00" to "null"),
            "array" to ("8101" to "[1]"),
            "map" to ("a1616101" to "{\"a\":1}"),
            "full-date (tag 1004)" to ("d903ec6a313939302d30312d3031" to "\"1990-01-01\""),
            "date-time (tag 0) keeps its string as issued" to
                    ("c07819323032362d31302d32325430393a31353a33302b30313a3030" to "\"2026-10-22T09:15:30+01:00\""),
            "positive bignum (tag 2)" to ("c249010000000000000000" to "\"AQAAAAAAAAAA\""),
            "negative bignum (tag 3)" to ("c349010000000000000000" to "\"~AQAAAAAAAAAA\""),
            "positive bignum with an indefinite byte string" to ("c25f41014102ff" to "\"AQI\""),
            "negative bignum with an indefinite byte string" to ("c35f41014102ff" to "\"~AQI\""),
            "expected base64url (tag 21)" to ("d542fbff" to "\"-_8\""),
            "expected base64 (tag 22)" to ("d642fbff" to "\"+/8=\""),
            "expected base16 (tag 23)" to ("d742fbff" to "\"FBFF\""),
            "encoding hint for nested byte strings" to ("d68142fbff" to "[\"+/8=\"]"),
        ).entries.asData(nameFn = { it.key }) test { (_, case) ->
            val (cbor, json) = case
            Cbor.decodeFromByteArray<CborObject>(cbor.hexToByteArray()).toRfc8949Json().toString() shouldBe json
        }
    }

    "data elements of an IssuerSignedItem" - {
        "the original element value is converted" {
            item("d903ec6a313939302d30312d3031").toDcqlClaimValue().toString() shouldBe "\"1990-01-01\""
        }
        "an array is not converted like a byte string, so it does not match its base64url" {
            // the CBOR array [1], which an unregistered element was decoded to as raw bytes, base64url "gQE"
            val value = item("8101").toDcqlClaimValue()
            value.toString() shouldBe "[1]"
            matches(value, DCQLExpectedClaimValue.StringValue("gQE")) shouldBe false
        }
        "an integer is matched as its CBOR value, not as a value of a display encoder" {
            val value = item("00").toDcqlClaimValue()
            matches(value, DCQLExpectedClaimValue.IntegerValue(0)) shouldBe true
            matches(value, DCQLExpectedClaimValue.StringValue("display")) shouldBe false
        }
        "an item that can not be read is null" {
            ByteStringWrapper(IssuerSignedItem(0u, byteArrayOf(0), "x", "unused"), byteArrayOf())
                .toDcqlClaimValue() shouldBe JsonNull
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
            ).getOrThrow().shouldBeInstanceOf<DCQLMatchingResult<*>>()
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

/**
 * An `IssuerSignedItem` as encoded in an ISO mdoc, whose element value is the CBOR item [elementValue] in hex. Only its
 * encoding is converted, the decoded item is a placeholder.
 */
@OptIn(ExperimentalStdlibApi::class)
private fun item(elementValue: String) = ByteStringWrapper(
    IssuerSignedItem(0u, byteArrayOf(0), "x", "unused"),
    ("a4" + "686469676573744944" + "00" + "6672616e646f6d" + "4100" +
            "71656c656d656e744964656e746966696572" + "6178" + "6c656c656d656e7456616c7565" + elementValue).hexToByteArray(),
)

private fun matches(value: JsonElement, expected: DCQLExpectedClaimValue) = DCQLIsoMdocClaimsQuery(
    path = DCQLClaimsPathPointer("namespace", "x"),
    values = listOf(expected),
).executeClaimsQueryAgainstCredential(
    DCQLCredentialClaimStructure.IsoMdocStructure(mapOf("namespace" to mapOf("x" to value)))
).isSuccess
