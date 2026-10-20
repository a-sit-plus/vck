@file:OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)

package at.asitplus.etsi

import at.asitplus.etsi.relyingParty.WrpConstants
import at.asitplus.etsi.relyingParty.WrpLangString
import at.asitplus.etsi.relyingParty.WrpPayload
import at.asitplus.etsi.relyingParty.WrpStatus
import at.asitplus.etsi.relyingParty.WrpStatusList
import at.asitplus.etsi.relyingParty.WrpSupervisoryAuthority
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlinx.serialization.cbor.Cbor
import kotlin.time.Instant

val WrpServiceDescriptionsSerializationTest by matrixSuite {
    val shop = WrpLangString(lang = "en", value = "Shop")
    val laden = WrpLangString(lang = "de", value = "Laden")
    val payload = WrpPayload(
        subjectIdentifier = "LEIXG-529900T8BM49AURSDO55",
        country = "AT",
        registryUri = "https://registrar.example.com",
        srvDescription = listOf(listOf(shop, laden)),
        entitlements = listOf(WrpConstants.ENTITLEMENT_SERVICE_PROVIDER),
        privacyPolicies = listOf("https://example.com/privacy"),
        infoUris = listOf("https://example.com/info"),
        supportUris = listOf("https://example.com/support"),
        supervisoryAuthority = WrpSupervisoryAuthority(emails = listOf("dpa@example.com")),
        policyId = listOf(WrpConstants.POLICY_IDENTIFIER),
        certificatePolicy = "https://registrar.example.com/policy",
        iat = Instant.fromEpochSeconds(1_700_000_000),
        status = WrpStatus(WrpStatusList(idx = 0u, uri = "https://registrar.example.com/status")),
    )
    val nestedJson = """"srv_description":[[{"lang":"en","value":"Shop"},{"lang":"de","value":"Laden"}]]"""
    val flatJson = """"srv_description":[{"lang":"en","value":"Shop"},{"lang":"de","value":"Laden"}]"""
    // [{"lang":"en","value":"Shop"},{"lang":"de","value":"Laden"}]
    val flatCbor = "82a2646c616e6762656e6576616c75656453686f70a2646c616e676264656576616c7565654c6164656e"
    val nestedCbor = "81$flatCbor"

    "JSON encodes an array of arrays" {
        joseCompliantSerializer.encodeToString(WrpPayload.serializer(), payload) shouldContain nestedJson
    }

    "JSON decodes an array of arrays and a single array alike" {
        val nested = joseCompliantSerializer.encodeToString(WrpPayload.serializer(), payload)
        joseCompliantSerializer.decodeFromString(WrpPayload.serializer(), nested) shouldBe payload
        joseCompliantSerializer.decodeFromString(WrpPayload.serializer(), nested.replace(nestedJson, flatJson)) shouldBe
                payload
    }

    "JSON keeps several arrays" {
        val nested = joseCompliantSerializer.encodeToString(WrpPayload.serializer(), payload)
        val several = """"srv_description":[[{"lang":"en","value":"Shop"}],[{"lang":"de","value":"Laden"}]]"""
        joseCompliantSerializer.decodeFromString(WrpPayload.serializer(), nested.replace(nestedJson, several))
            .srvDescription shouldBe listOf(listOf(shop), listOf(laden))
    }

    "JSON rejects an empty array and arrays mixed with objects" - {
        listOf(
            """"srv_description":[]""",
            """"srv_description":[[{"lang":"en","value":"Shop"}],{"lang":"de","value":"Laden"}]""",
            """"srv_description":[{"lang":"en","value":"Shop"},[{"lang":"de","value":"Laden"}]]""",
            """"srv_description":["Shop"]""",
        ).asData() test { srvDescription ->
            val nested = joseCompliantSerializer.encodeToString(WrpPayload.serializer(), payload)
            shouldThrowAny {
                joseCompliantSerializer.decodeFromString(WrpPayload.serializer(), nested.replace(nestedJson, srvDescription))
            }
        }
    }

    "CBOR encodes an array of arrays" {
        Cbor.CoseCompliant.encodeToByteArray(WrpPayload.serializer(), payload).toHexString() shouldContain nestedCbor
    }

    "CBOR decodes an array of arrays and a single array alike" {
        val nested = Cbor.CoseCompliant.encodeToByteArray(WrpPayload.serializer(), payload).toHexString()
        Cbor.CoseCompliant.decodeFromByteArray(WrpPayload.serializer(), nested.hexToByteArray()) shouldBe payload
        Cbor.CoseCompliant.decodeFromByteArray(
            WrpPayload.serializer(),
            nested.replace(nestedCbor, flatCbor).hexToByteArray()
        ) shouldBe payload
    }

    "CBOR keeps several arrays" {
        val nested = Cbor.CoseCompliant.encodeToByteArray(WrpPayload.serializer(), payload).toHexString()
        // [[{"lang":"en","value":"Shop"}],[{"lang":"de","value":"Laden"}]]
        val several = "8281a2646c616e6762656e6576616c75656453686f7081a2646c616e676264656576616c7565654c6164656e"
        Cbor.CoseCompliant.decodeFromByteArray(
            WrpPayload.serializer(),
            nested.replace(nestedCbor, several).hexToByteArray()
        ).srvDescription shouldBe listOf(listOf(shop), listOf(laden))
    }

    "CBOR rejects arrays mixed with objects" - {
        listOf(
            // [[{"lang":"en","value":"Shop"}],{"lang":"de","value":"Laden"}]
            "8281a2646c616e6762656e6576616c75656453686f70a2646c616e676264656576616c7565654c6164656e",
            // [{"lang":"en","value":"Shop"},[{"lang":"de","value":"Laden"}]]
            "82a2646c616e6762656e6576616c75656453686f7081a2646c616e676264656576616c7565654c6164656e",
            // ["Shop"]
            "816453686f70",
        ).asData() test { srvDescription ->
            val nested = Cbor.CoseCompliant.encodeToByteArray(WrpPayload.serializer(), payload).toHexString()
            shouldThrowAny {
                Cbor.CoseCompliant.decodeFromByteArray(
                    WrpPayload.serializer(),
                    nested.replace(nestedCbor, srvDescription).hexToByteArray()
                )
            }
        }
    }
}
