package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.QesAuthorization
import at.asitplus.openid.TransactionData
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.sha_256
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.wallet.lib.data.Base64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.ktor.util.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Test vectors taken from "Transaction Data entries as defined in D3.1: UC Specification WP3"
 */
class TransactionDataInterop : FreeSpec({

    val transactionDataTest = QCertCreationAcceptance(
        qcTermsConditionsUri = "abc",
        qcHash = "cde".decodeBase64Bytes(),
        qcHashAlgorithmOid = KnownOIDs.sha_256,
        credentialIds = setOf()
    )

    "Polymorphic Serialization is stable" {
        val encoded =
            vckJsonSerializer.encodeToString(TransactionData.serializer(), transactionDataTest)
        encoded shouldContain "type"
        vckJsonSerializer.decodeFromString(TransactionData.serializer(), encoded)
            .shouldBe(transactionDataTest)
    }

    "Base64Url Serialization is stable" {
        val encoded = vckJsonSerializer.encodeToString(Base64URLTransactionDataSerializer, transactionDataTest)
        vckJsonSerializer.decodeFromString(Base64URLTransactionDataSerializer, encoded).shouldBe(transactionDataTest)
    }

    "DifInputDescriptor Sanity Check" {
        val input = DifInputDescriptor(id = "123")
        val serialized = vckJsonSerializer.encodeToString(input)
        serialized.shouldNotContain("type")
        vckJsonSerializer.decodeFromString(InputDescriptor.serializer(), serialized).shouldBe(input)
    }

    "QesAuthorization can be parsed" - {
        val testVector =
            "ewogICJ0eXBlIjogInFlc19hdXRob3JpemF0aW9uIiwKICAiY3JlZGVudGlhbF9pZHMiOiBbXSwKICAic2lnbmF0dXJlUXVhbGlmaWVyIjogImV1X2VpZGFzX3FlcyIsCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUZyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsCiAgImRvY3VtZW50RGlnZXN0cyI6IFsKICAgIHsKICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLAogICAgICAiaGFzaCI6ICJzVE9nd09tKzQ3NGdGajBxMHgxaVNOc3BLcWJjc2U0SWVpcWxEZy9IV3VJPSIsCiAgICAgICJoYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiLAogICAgICAiZG9jdW1lbnRMb2NhdGlvbl91cmkiOiAiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250cmFjdC0wMS5wZGY_dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwKICAgICAgImRvY3VtZW50TG9jYXRpb25fbWV0aG9kIjogewogICAgICAgICJkb2N1bWVudF9hY2Nlc3NfbW9kZSI6ICJPVFAiLAogICAgICAgICJvbmVUaW1lUGFzc3dvcmQiOiAibXlGaXJzdFBhc3N3b3JkIgogICAgICB9LAogICAgICAiRFRCUy9SIjogIlZZRGw0b1RlSjVUbUlQQ1hLZFRYMU1TV1JMSTlDS1ljeU1SejZ4bGFHZyIsCiAgICAgICJEVEJTL1JIYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCiAgICB9CiAgXSwKICAicHJvY2Vzc0lEIjogImVPWjZVd1h5ZUZMSzk4RG81MXgzM2ZtdXY0T3FBejVaYzRsc2hLTnRFZ1E9Igp9"
        val transactionData = vckJsonSerializer.decodeFromString(
            Base64URLTransactionDataSerializer, vckJsonSerializer.encodeToString(testVector)
        )

        "Data classes are deserialized correctly" {
            transactionData.shouldBeInstanceOf<QesAuthorization>()
            transactionData.documentDigests shouldNotBe emptyList<RqesDocumentDigestEntry>()
            transactionData.documentDigests.first().documentLocationMethod shouldNotBe null
            transactionData.documentDigests.first().documentLocationMethod!!.documentAccessMode shouldBe RqesDocumentDigestEntry.DocumentLocationMethod.DocumentAccessMode.OTP
            transactionData.documentDigests.first().documentLocationMethod!!.oneTimePassword shouldNotBe null
        }


        "Encoding-Decoding is correct" {
            val expected = vckJsonSerializer.decodeFromString<JsonElement>(
                testVector.decodeToByteArray(Base64UrlStrict).decodeToString()
            ).canonicalize() as JsonObject
            val actual =
                vckJsonSerializer.encodeToJsonElement(TransactionData.serializer(), transactionData)
                    .canonicalize() as JsonObject

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
                vckJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
            } shouldBe expectedDocumentDigest["dtbsr"]?.let {
                vckJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
            }
            actualDocumentDigest["dtbsrHashAlgorithmOID"] shouldBe expectedDocumentDigest["dtbsrHashAlgorithmOID"]
            //In order to deal with padding we deserialize and compare the bytearrays
            actualDocumentDigest["hash"]?.let {
                vckJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
            } shouldBe expectedDocumentDigest["hash"]?.let {
                vckJsonSerializer.decodeFromJsonElement(ByteArrayBase64Serializer, it)
            }
            actualDocumentDigest["hashHashAlgorithmOID"] shouldBe expectedDocumentDigest["hashHashAlgorithmOID"]
        }
    }

    "QCertCreationAcceptance can be parsed" - {
        val testVector =
            "ewogICJ0eXBlIjogInFjZXJ0X2NyZWF0aW9uX2FjY2VwdGFuY2UiLAogICJjcmVkZW50aWFsX2lkcyI6IFtdLAogICJRQ190ZXJtc19jb25kaXRpb25zX3VyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3RvcyIsCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQytEK2I3T0NyRG84SU9HWmpTWDgvTT0iLAogICJRQ19oYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCn0"

        val transactionData = vckJsonSerializer.decodeFromString(
            Base64URLTransactionDataSerializer, vckJsonSerializer.encodeToString(testVector)
        )
        "Data classes are deserialized correctly" {
            transactionData.shouldBeInstanceOf<QCertCreationAcceptance>()
        }

        "Encoding-Decoding is correct" {
            val expected = vckJsonSerializer.decodeFromString<JsonElement>(
                testVector.decodeToByteArray(Base64UrlStrict).decodeToString()
            ).canonicalize()

            vckJsonSerializer.encodeToJsonElement(TransactionData.serializer(), transactionData)
                .canonicalize().shouldBe(expected)
        }
    }
})

/**
 * Sorts all entries of the JsonElement which is necessary in case we want to compare two objects
 */
fun JsonElement.canonicalize(serializer: Json = vckJsonSerializer): JsonElement = when (this) {
    is JsonObject -> JsonObject(this.entries.sortedBy { it.key }.sortedBy { serializer.encodeToString(it.value) }
        .associate { it.key to it.value.canonicalize(serializer) })

    is JsonArray -> JsonArray(this.map { it.canonicalize() }.sortedBy { serializer.encodeToString(it) })
    is JsonPrimitive -> this
    JsonNull -> this
}