package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.rqes.QesInputDescriptor
import at.asitplus.rqes.collection_entries.TransactionData
import at.asitplus.rqes.rdcJsonSerializer
import at.asitplus.rqes.serializers.Base64URLTransactionDataSerializer
import at.asitplus.signum.indispensable.asn1.KnownOIDs.sha_256
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.PolymorphicSerializer
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

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
                        "ewogICJ0eXBlIjogInFlc19hdXRob3JpemF0aW9uIiwKICAic2lnbmF0dXJlUXVhbGlmaWVyIjogImV1X2VpZGFzX3FlcyIsCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUZyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsCiAgImRvY3VtZW50RGlnZXN0cyI6IFsKICAgIHsKICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLAogICAgICAiaGFzaCI6ICJzVE9nd09tKzQ3NGdGajBxMHgxaVNOc3BLcWJjc2U0SWVpcWxEZy9IV3VJPSIsCiAgICAgICJoYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLAogICAgICAiZG9jdW1lbnRMb2NhdGlvbl91cmkiOiAiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250cmFjdC0wMS5wZGY/dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwKICAgICAgImRvY3VtZW50TG9jYXRpb25fbWV0aG9kIjogewogICAgICAgICJkb2N1bWVudF9hY2Nlc3NfbW9kZSI6ICJPVFAiLAogICAgICAgICJvbmVUaW1lUGFzc3dvcmQiOiAibXlGaXJzdFBhc3N3b3JkIgogICAgICB9LAogICAgICAiRFRCUy9SIjogIlZZRGw0b1RlSjVUbUlQQ1hLZFRYMU1TV1JMSTlDS1ljeU1SejZ4bGFHZyIsCiAgICAgICJEVEJTL1JIYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCiAgICB9CiAgXSwKICAicHJvY2Vzc0lEIjogImVPWjZVd1h5ZUZMSzk4RG81MXgzM2ZtdXY0T3FBejVaYzRsc2hLTnRFZ1E9Igp9",
                        "ewogICJ0eXBlIjogInFjZXJ0X2NyZWF0aW9uX2FjY2VwdGFuY2UiLAogICJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3RvcyIsCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQytEK2I3T0NyRG84SU9HWmpTWDgvTT0iLAogICJRQ19oYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCn0="
                    ]
                }
            ]
        }
    """.trimIndent().replace("\n", "").replace("\r", "").replace(" ", "")

    val transactionDataTest = TransactionData.QCertCreationAcceptance(
        qcTermsConditionsUri = "abc",
        qcHash = "cde".decodeBase64Bytes(),
        qcHashAlgorithmOid = sha_256
    )

    "Serialization is stable" {
        val encoded = rdcJsonSerializer.encodeToString<TransactionData>(transactionDataTest)
        rdcJsonSerializer.decodeFromString<TransactionData>(encoded)
            .shouldBe(transactionDataTest)
    }

    "InputDescriptor serialize" {
        val input = QesInputDescriptor(
            id = "123",
            transactionData = listOf(transactionDataTest)
        )
        val serialized = rdcJsonSerializer.encodeToString(input)
        rdcJsonSerializer.decodeFromString(PolymorphicSerializer(InputDescriptor::class), serialized)
            .shouldBe(input)
    }

    "TransactionDataEntry.QesAuthorization can be parsed" {
        val testVector =
            "ewogICJ0eXBlIjogInFlc19hdXRob3JpemF0aW9uIiwKICAic2lnbmF0dXJlUXVhbGlmaWVyIjogImV1X2VpZGFzX3FlcyIsCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUZyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsCiAgImRvY3VtZW50RGlnZXN0cyI6IFsKICAgIHsKICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLAogICAgICAiaGFzaCI6ICJzVE9nd09tKzQ3NGdGajBxMHgxaVNOc3BLcWJjc2U0SWVpcWxEZy9IV3VJPSIsCiAgICAgICJoYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLAogICAgICAiZG9jdW1lbnRMb2NhdGlvbl91cmkiOiAiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250cmFjdC0wMS5wZGY/dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwKICAgICAgImRvY3VtZW50TG9jYXRpb25fbWV0aG9kIjogewogICAgICAgICJkb2N1bWVudF9hY2Nlc3NfbW9kZSI6ICJPVFAiLAogICAgICAgICJvbmVUaW1lUGFzc3dvcmQiOiAibXlGaXJzdFBhc3N3b3JkIgogICAgICB9LAogICAgICAiRFRCUy9SIjogIlZZRGw0b1RlSjVUbUlQQ1hLZFRYMU1TV1JMSTlDS1ljeU1SejZ4bGFHZyIsCiAgICAgICJEVEJTL1JIYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCiAgICB9CiAgXSwKICAicHJvY2Vzc0lEIjogImVPWjZVd1h5ZUZMSzk4RG81MXgzM2ZtdXY0T3FBejVaYzRsc2hLTnRFZ1E9Igp9"
        val transactionData = rdcJsonSerializer.decodeFromString(
            Base64URLTransactionDataSerializer,
            rdcJsonSerializer.encodeToString(testVector)
        )

        val expected = rdcJsonSerializer.decodeFromString<JsonElement>(
            testVector.decodeToByteArray(Base64UrlStrict).decodeToString()
        ).canonicalize() as JsonObject
        val actual = rdcJsonSerializer.encodeToJsonElement(transactionData).canonicalize() as JsonObject

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
            rdcJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
        } shouldBe expectedDocumentDigest["dtbsr"]?.let {
            rdcJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
        }
        actualDocumentDigest["dtbsrHashAlgorithmOID"] shouldBe expectedDocumentDigest["dtbsrHashAlgorithmOID"]
        //In order to deal with padding we deserialize and compare the bytearrays
        actualDocumentDigest["hash"]?.let {
            rdcJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
        } shouldBe expectedDocumentDigest["hash"]?.let {
            rdcJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
        }
        actualDocumentDigest["hashHashAlgorithmOID"] shouldBe expectedDocumentDigest["hashHashAlgorithmOID"]
    }

    "TransactionDataEntry.QCertCreationAcceptance can be parsed" {
        val testVector =
            "ewogICJ0eXBlIjogInFjZXJ0X2NyZWF0aW9uX2FjY2VwdGFuY2UiLAogICJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3RvcyIsCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQytEK2I3T0NyRG84SU9HWmpTWDgvTT0iLAogICJRQ19oYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCn0="

        val transactionData = rdcJsonSerializer.decodeFromString(
            Base64URLTransactionDataSerializer,
            rdcJsonSerializer.encodeToString(testVector)
        )

        val expected = rdcJsonSerializer.decodeFromString<JsonElement>(
            testVector.decodeToByteArray(Base64UrlStrict).decodeToString()
        ).canonicalize()

        rdcJsonSerializer.encodeToJsonElement(transactionData).canonicalize()
            .shouldBe(expected)
    }

    "The presentation Definition can be parsed" {
        val presentationDefinition =
            rdcJsonSerializer.decodeFromString<PresentationDefinition>(presentationDefinitionAsJsonString)
        val first = presentationDefinition.inputDescriptors.first()
            .shouldBeInstanceOf<QesInputDescriptor>()
        @Suppress("DEPRECATION")
        first.transactionData shouldNotBe null
    }
})

/**
 * Sorts all entries of the JsonElement which is necessary in case we want to compare two objects
 */
fun JsonElement.canonicalize(): JsonElement =
    when (this) {
        is JsonObject -> JsonObject(this.entries.sortedBy { it.key }
            .sortedBy { rdcJsonSerializer.encodeToString(it.value) }.associate { it.key to it.value.canonicalize() })

        is JsonArray -> JsonArray(this.map { it.canonicalize() }.sortedBy { rdcJsonSerializer.encodeToString(it) })
        is JsonPrimitive -> this
        JsonNull -> this
    }