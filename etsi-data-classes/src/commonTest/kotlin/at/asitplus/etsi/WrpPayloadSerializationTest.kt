@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.etsi

import at.asitplus.etsi.relyingParty.WrpConstants
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.etsi.relyingParty.WrpSupervisoryAuthority
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

val WrpPayloadSerializationTest by matrixSuite {
    // ETSI TS 119 475 V1.2.1, Annex C, whose intermediary carries `name` instead of `sname` (Table 10)
    val annexC = """
        {
          "name": "Example Company",
          "sub_ln": "Example Company GmbH",
          "sub": "LEIXG-529900T8BM49AURSDO55",
          "country": "DE",
          "registry_uri": "https://registrar.com",
          "srv_description": [[
            {"lang": "en-US", "value": "Awesome Service by Example Company"},
            {"lang": "de-DE", "value": "Super Dienst von Example Company"}
          ]],
          "entitlements": ["https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"],
          "privacy_policy": "https://example.com/privacy-policy",
          "info_uri": "https://example.com/info",
          "support_uri": "https://example.com/support",
          "supervisory_authority": {
            "email": "supervisory@dpa.com",
            "phone": "+49 123 4567890",
            "uri": "https://dpa.com/supervisory-authority"
          },
          "policy_id": ["0.4.0.19475.3.1"],
          "certificate_policy": "https://registrar.com/certificate-policy",
          "iat": 1683000000,
          "status": {"status_list": {"idx": 0, "uri": "https://example.com/statuslists/1"}},
          "purpose": [
            {"lang": "en-US", "value": "Required for checking the minimum age"},
            {"lang": "de-DE", "value": "Benötigt für die Überprüfung des Mindestalters"}
          ],
          "credentials": [
            {
              "format": "dc+sd-jwt",
              "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
              "claim": [{"path": ["age_equal_or_over", "18"]}]
            },
            {
              "format": "mso_mdoc",
              "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"},
              "claim": [{"path": ["eu.europa.ec.eudi.pid.1", "age_over_18"]}]
            }
          ],
          "provides_attestations": [
            {"format": "dc+sd-jwt", "meta": {"vct_values": ["https://example.com/attestations/age_over_18"]}}
          ],
          "intermediary": {"sub": "LEIXG-INTERMEDIARY-1234567890", "name": "Intermediary Services Ltd."}
        }
    """.trimIndent()
    val annexCObject = joseCompliantSerializer.parseToJsonElement(annexC).jsonObject

    fun JsonObject.without(key: String) = JsonObject(this - key)
    fun JsonObject.with(key: String, json: String) =
        JsonObject(this + (key to joseCompliantSerializer.parseToJsonElement(json)))
    fun decode(json: JsonObject) = joseCompliantSerializer.decodeFromJsonElement(WrpPayload.serializer(), json)

    "decodes the example of Annex C" {
        val payload = decode(annexCObject)

        payload.policyId shouldBe listOf(WrpConstants.POLICY_IDENTIFIER)
        payload.privacyPolicy shouldBe "https://example.com/privacy-policy"
        payload.providesAttestations?.single()?.claim.shouldBeNull()
        payload.intermediary?.sub shouldBe "LEIXG-INTERMEDIARY-1234567890"
        payload.intermediary?.sname.shouldBeNull()
    }

    "decodes the single strings of Annex C as lists, and keeps the first one in the deprecated fields" {
        val payload = decode(annexCObject)

        payload.subjectLegalNames shouldBe listOf("Example Company GmbH")
        payload.infoUris shouldBe listOf("https://example.com/info")
        payload.supportUris shouldBe listOf("https://example.com/support")
        payload.supervisoryAuthority shouldBe WrpSupervisoryAuthority(
            emails = listOf("supervisory@dpa.com"),
            phones = listOf("+49 123 4567890"),
            uris = listOf("https://dpa.com/supervisory-authority"),
        )
        @Suppress("DEPRECATION")
        payload.supportUri shouldBe "https://example.com/support"
    }

    "decodes arrays of several strings, and always encodes arrays" {
        val several = """["https://example.com/support","mailto:support@example.com"]"""
        val payload = decode(annexCObject.with("support_uri", several))
        payload.supportUris shouldBe listOf("https://example.com/support", "mailto:support@example.com")

        val encoded = joseCompliantSerializer.encodeToString(WrpPayload.serializer(), decode(annexCObject))
        encoded shouldContain """"sub_ln":["Example Company GmbH"]"""
        encoded shouldContain """"privacy_policy":"https://example.com/privacy-policy""""
        encoded shouldContain """"info_uri":["https://example.com/info"]"""
        encoded shouldContain """"support_uri":["https://example.com/support"]"""
        encoded shouldContain """"email":["supervisory@dpa.com"]"""
    }

    "rejects an empty array or other values than strings" - {
        listOf("[]", "1", "[1]", "{}", "null").asData() test { value ->
            shouldThrowAny { decode(annexCObject.with("support_uri", value)) }
        }
    }

    // Table 7 maps privacy_policy from the single policyURI of clause B.2.8
    "rejects other values than a single string for privacy_policy" - {
        listOf("""["https://example.com/privacy-policy"]""", "[]", "1", "{}", "null").asData() test { value ->
            shouldThrowAny { decode(annexCObject.with("privacy_policy", value)) }
        }
    }

    "CBOR decodes a single string or an array, and encodes an array" {
        val serializer = WrpSupervisoryAuthority.serializer()
        val expected = WrpSupervisoryAuthority(emails = listOf("a"))
        // {"email": "a"}
        Cbor.CoseCompliant.decodeFromByteArray(serializer, "a165656d61696c6161".hexToByteArray()) shouldBe expected
        // {"email": ["a"]}
        Cbor.CoseCompliant.decodeFromByteArray(serializer, "a165656d61696c816161".hexToByteArray()) shouldBe expected
        Cbor.CoseCompliant.encodeToByteArray(serializer, expected).toHexString() shouldContain "65656d61696c816161"
    }

    "encodes policy_id, which has no default" {
        joseCompliantSerializer.encodeToString(WrpPayload.serializer(), decode(annexCObject)) shouldContain
                """"policy_id":["${WrpConstants.POLICY_IDENTIFIER}"]"""
    }

    "decodes optional fields as absent" {
        val payload = listOf("name", "info_uri", "purpose", "credentials", "provides_attestations", "intermediary")
            .fold(annexCObject) { json, key -> json.without(key) }
            .let { decode(it) }

        payload.name.shouldBeNull()
        payload.infoUris.shouldBeNull()
        payload.purpose.shouldBeNull()
        payload.credentials.shouldBeNull()
        payload.providesAttestations.shouldBeNull()
        payload.intermediary.shouldBeNull()
    }

    "rejects a payload without a required field" - {
        listOf("policy_id", "privacy_policy", "support_uri", "supervisory_authority").asData() test { key ->
            shouldThrowAny { decode(annexCObject.without(key)) }
        }
    }

    "rejects empty arrays of at least one entry, and an intermediary without sub" - {
        listOf(
            "entitlements" to "[]",
            "srv_description" to "[]",
            "purpose" to "[]",
            "credentials" to "[]",
            "credentials" to """[{"format":"mso_mdoc","meta":{"doctype_value":"a"},"claim":[]}]""",
            "credentials" to """[{"format":"mso_mdoc","meta":{"doctype_value":"a"},"claim":[{"path":["a"],"values":[]}]}]""",
            "intermediary" to """{"sname":"Intermediary Services Ltd."}""",
        ).asData(nameFn = { "${it.first}: ${it.second}" }) test { field ->
            shouldThrowAny { decode(annexCObject.with(field.first, field.second)) }
        }
    }
}
