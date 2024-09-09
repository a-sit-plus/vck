package at.asitplus.wallet.lib.data

import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.dif.rqes.Base64URLTransactionDataSerializer
import at.asitplus.dif.rqes.TransactionDataEntry
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement

/**
 * Test vectors taken from "Transaction Data entries as defined in D3.1: UC Specification WP3"
 */
class TransactionDataInterop : FreeSpec({
    val presentationDefinitionAsJsonString = """
        {
            "id": "d76c51b7-ea90-49bb-8368-6b3d194fc131",
            "input_descriptors": [
                {
                    "id": "IdentityCredential",
                    "format": {
                        "vc+sd-jwt": {}
                    },
                    "constraints": {
                        "limit_disclosure": "required",
                        "fields": [
                            {
                                "path": ["$.vct"],
                                "filter": {
                                    "type": "string",
                                    "const": "IdentityCredential"
                                }
                            },
                            {
                                "path": ["$.family_name"]
                            },
                            {
                                "path": ["$.given_name"]
                            }
                        ]
                    },
                    "transaction_data": [
                        "ewogICJ0eXBlIjogInFlc19hdXRob3JpemF0aW9uIiwKICAic2lnbmF0dXJlUXVhbGlmaWVyIjogImV1X2VpZGFzX3FlcyIsCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUZyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsCiAgImRvY3VtZW50RGlnZXN0cyI6IFsKICAgIHsKICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLAogICAgICAiaGFzaCI6ICJzVE9nd09tKzQ3NGdGajBxMHgxaVNOc3BLcWJjc2U0SWVpcWxEZy9IV3VJPSIsCiAgICAgICJoYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLAogICAgICAiZG9jdW1lbnRMb2NhdGlvbl91cmkiOiAiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250cmFjdC0wMS5wZGY_dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwKICAgICAgImRvY3VtZW50TG9jYXRpb25fbWV0aG9kIjogewogICAgICAgICJtZXRob2QiOiB7CiAgICAgICAgICAidHlwZSI6ICJwdWJsaWMiCiAgICAgICAgfQogICAgICB9LAogICAgICAiZHRic3IiOiAiVllEbDRvVGVKNVRtSVBDWEtkVFgxTVNXUkxJOUNLWWN5TVJ6NnhsYUdnIiwKICAgICAgImR0YnNySGFzaEFsZ29yaXRobU9JRCI6ICIyLjE2Ljg0MC4xLjEwMS4zLjQuMi4xIgogICAgfQogIF0sCiAgInByb2Nlc3NJRCI6ICJlT1o2VXdYeWVGTEs5OERvNTF4MzNmbXV2NE9xQXo1WmM0bHNoS050RWdRPSIKfQ",
                        "ewogICJ0eXBlIjogInFjZXJ0X2NyZWF0aW9uX2FjY2VwdGFuY2UiLAogICJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3RvcyIsCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQytEK2I3T0NyRG84SU9HWmpTWDgvTT0iLAogICJRQ19oYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCn0="
                    ]
                }
            ]
        }
    """.trimIndent().replace("\n", "").replace("\r", "").replace(" ", "")

    val transactionDataTest = TransactionDataEntry.QCertCreationAcceptance(
        qcTermsConditionsUri = "abc",
        qcHash = "cde".decodeBase64Bytes(),
        qcHashAlgorithmOID = ObjectIdentifier("2.16.840.1.101.3.4.2.1")
    )

    "Serialization is stable" {
        val test = vckJsonSerializer.encodeToString<TransactionDataEntry>(transactionDataTest)
        val test2 = vckJsonSerializer.decodeFromString<TransactionDataEntry>(test)
        test2 shouldBe transactionDataTest
    }

    "Inputdesriptor serialize" {
        val test = InputDescriptor(
            id = "123",
            transactionData = listOf(transactionDataTest)
        )
        val serialized = vckJsonSerializer.encodeToString(test)
        val deserialized = vckJsonSerializer.decodeFromString<InputDescriptor>(serialized)
        deserialized shouldBe test
    }

    "TransactionDataEntry.QesAuthorization can be parsed" {
        val testVector =
            "ewogICJ0eXBlIjogInFlc19hdXRob3JpemF0aW9uIiwKICAic2lnbmF0dXJlUXVhbGlmaWVyIjogImV1X2VpZGFzX3FlcyIsCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUZyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsCiAgImRvY3VtZW50RGlnZXN0cyI6IFsKICAgIHsKICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLAogICAgICAiaGFzaCI6ICJzVE9nd09tKzQ3NGdGajBxMHgxaVNOc3BLcWJjc2U0SWVpcWxEZy9IV3VJPSIsCiAgICAgICJoYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLAogICAgICAiZG9jdW1lbnRMb2NhdGlvbl91cmkiOiAiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250cmFjdC0wMS5wZGY_dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwKICAgICAgImRvY3VtZW50TG9jYXRpb25fbWV0aG9kIjogewogICAgICAgICJtZXRob2QiOiB7CiAgICAgICAgICAidHlwZSI6ICJwdWJsaWMiCiAgICAgICAgfQogICAgICB9LAogICAgICAiZHRic3IiOiAiVllEbDRvVGVKNVRtSVBDWEtkVFgxTVNXUkxJOUNLWWN5TVJ6NnhsYUdnIiwKICAgICAgImR0YnNySGFzaEFsZ29yaXRobU9JRCI6ICIyLjE2Ljg0MC4xLjEwMS4zLjQuMi4xIgogICAgfQogIF0sCiAgInByb2Nlc3NJRCI6ICJlT1o2VXdYeWVGTEs5OERvNTF4MzNmbXV2NE9xQXo1WmM0bHNoS050RWdRPSIKfQ"
        val transactionData = runCatching {
            vckJsonSerializer.decodeFromString(
                Base64URLTransactionDataSerializer,
                vckJsonSerializer.encodeToString(testVector)
            )
        }.getOrNull()
        transactionData shouldNotBe null
        val expected = vckJsonSerializer.decodeFromString<JsonElement>(
            testVector.decodeToByteArray(Base64UrlStrict).decodeToString()
        ).canonicalize() as JsonObject
        val actual = vckJsonSerializer.encodeToJsonElement(transactionData).canonicalize() as JsonObject

        //Manual comparison of every member to deal with Base64 encoding below
        actual["credentialID"] shouldBe expected["credentialID"]
        actual["processID"] shouldBe expected["processID"]
        actual["signatureQualifier"] shouldBe expected["signatureQualifier"]
        actual["type"] shouldBe expected["type"]

        val expectedDocumentDigest = (expected["documentDigests"] as JsonArray).first() as JsonObject
        val actualDocumentDigest = (actual["documentDigests"] as JsonArray).first() as JsonObject

        actualDocumentDigest["documentLocation_method"] shouldBe expectedDocumentDigest["documentLocation_method"]
        actualDocumentDigest["documentLocation_uri"] shouldBe expectedDocumentDigest["documentLocation_uri"]

        //In order to deal with padding we deserialize and compare the bytearrays
        actualDocumentDigest["dtbsr"]?.let {
            vckJsonSerializer.decodeFromJsonElement(
                ByteArrayBase64Serializer,
                it
            )
        } shouldBe expectedDocumentDigest["dtbsr"]?.let {
            vckJsonSerializer.decodeFromJsonElement(
                ByteArrayBase64Serializer,
                it
            )
        }
        actualDocumentDigest["dtbsrHashAlgorithmOID"] shouldBe expectedDocumentDigest["dtbsrHashAlgorithmOID"]
        //In order to deal with padding we deserialize and compare the bytearrays
        actualDocumentDigest["hash"]?.let {
            vckJsonSerializer.decodeFromJsonElement(
                ByteArrayBase64Serializer,
                it
            )
        } shouldBe expectedDocumentDigest["hash"]?.let {
            vckJsonSerializer.decodeFromJsonElement(
                ByteArrayBase64Serializer,
                it
            )
        }
        actualDocumentDigest["hashHashAlgorithmOID"] shouldBe expectedDocumentDigest["hashHashAlgorithmOID"]

    }

    "TransactionDataEntry.QCertCreationAcceptance can be parsed" {
        val testVector =
            "ewogICJ0eXBlIjogInFjZXJ0X2NyZWF0aW9uX2FjY2VwdGFuY2UiLAogICJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3RvcyIsCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQytEK2I3T0NyRG84SU9HWmpTWDgvTT0iLAogICJRQ19oYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCn0="
        val transactionData = runCatching {
            vckJsonSerializer.decodeFromString(
                Base64URLTransactionDataSerializer,
                vckJsonSerializer.encodeToString(testVector)
            )
        }.getOrNull()
        transactionData shouldNotBe null
        val expected = vckJsonSerializer.decodeFromString<JsonElement>(
            testVector.decodeToByteArray(Base64UrlStrict).decodeToString()
        ).canonicalize()
        val actual = vckJsonSerializer.encodeToJsonElement(transactionData).canonicalize()
        actual shouldBe expected
    }

    "The presentation Definition can be parsed" {
        val presentationDefinition =
            runCatching { vckJsonSerializer.decodeFromString<PresentationDefinition>(presentationDefinitionAsJsonString) }.getOrNull()
        Napier.d(presentationDefinition.toString())
        presentationDefinition shouldNotBe null
        presentationDefinition?.inputDescriptors?.first()?.transactionData shouldNotBe null
    }
})

/**
 * Sorts all entries of the JsonElement which is necessary in case we want to compare two objects
 */
fun JsonElement.canonicalize(): JsonElement =
    when (this) {
        is JsonObject -> JsonObject(this.entries.sortedBy { it.key }.associate { it.key to it.value.canonicalize() })
        is JsonArray -> JsonArray(this.map { it.canonicalize() }.sortedBy { vckJsonSerializer.encodeToString(it) })
        is JsonPrimitive -> this
        JsonNull -> this
    }