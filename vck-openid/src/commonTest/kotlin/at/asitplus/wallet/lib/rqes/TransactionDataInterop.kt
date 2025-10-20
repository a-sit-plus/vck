package at.asitplus.wallet.lib.rqes

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.InputDescriptor
import at.asitplus.openid.QCertCreationAcceptance
import at.asitplus.openid.QesAuthorization
import at.asitplus.openid.TransactionData
import at.asitplus.csc.collection_entries.RqesDocumentDigestEntry.DocumentLocationMethod
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.sha_256
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.wallet.lib.data.Base64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.oidvci.randomString
import com.benasher44.uuid.uuid4
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.random.Random

/**
 * Test vectors taken from "Transaction Data entries as defined in D3.1: UC Specification WP3"
 */
class TransactionDataInterop by testSuite{

    "Polymorphic Serialization is stable" {
        val input = QCertCreationAcceptance(
            credentialIds = setOf(),
            qcTermsConditionsUri = randomString(),
            qcHash = Random.nextBytes(32),
            qcHashAlgorithmOid = KnownOIDs.sha_256
        )
        val serialized = vckJsonSerializer.encodeToString(TransactionData.serializer(), input).also {
            it shouldContain "type"
        }

        vckJsonSerializer.decodeFromString(TransactionData.serializer(), serialized)
            .shouldBe(input)
    }

    "Base64Url Serialization is stable" {
        val input = QCertCreationAcceptance(
            credentialIds = setOf(),
            qcTermsConditionsUri = randomString(),
            qcHash = Random.nextBytes(32),
            qcHashAlgorithmOid = KnownOIDs.sha_256
        )
        val serialized = vckJsonSerializer.encodeToString(Base64URLTransactionDataSerializer, input)

        vckJsonSerializer.decodeFromString(Base64URLTransactionDataSerializer, serialized)
            .shouldBe(input)
    }

    "DifInputDescriptor Sanity Check" {
        val input = DifInputDescriptor(id = uuid4().toString())
        val serialized = vckJsonSerializer.encodeToString(input).also {
            it shouldNotContain "type"
        }

        vckJsonSerializer.decodeFromString(InputDescriptor.serializer(), serialized)
            .shouldBe(input)
    }

    "QesAuthorization can be parsed" - {
        val input = """
            ewogICJ0eXBlIjogInFlc19hdXRob3JpemF0aW9uIiwKICAiY3JlZGVudGlhbF9pZHMiOiBbXSwKICAic2lnbmF0dXJlUXVhbGlmaWVyIjog
            ImV1X2VpZGFzX3FlcyIsCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUZyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIs
            CiAgImRvY3VtZW50RGlnZXN0cyI6IFsKICAgIHsKICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLAogICAgICAiaGFzaCI6ICJz
            VE9nd09tKzQ3NGdGajBxMHgxaVNOc3BLcWJjc2U0SWVpcWxEZy9IV3VJPSIsCiAgICAgICJoYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQw
            LjEuMTAxLjMuNC4yLjEiLAogICAgICAiZG9jdW1lbnRMb2NhdGlvbl91cmkiOiAiaHR0cHM6Ly9wcm90ZWN0ZWQucnAuZXhhbXBsZS9jb250
            cmFjdC0wMS5wZGY_dG9rZW49SFM5bmFKS1d3cDkwMWhCY0szNDhJVUhpdUg4Mzc0IiwKICAgICAgImRvY3VtZW50TG9jYXRpb25fbWV0aG9k
            IjogewogICAgICAgICJkb2N1bWVudF9hY2Nlc3NfbW9kZSI6ICJPVFAiLAogICAgICAgICJvbmVUaW1lUGFzc3dvcmQiOiAibXlGaXJzdFBh
            c3N3b3JkIgogICAgICB9LAogICAgICAiRFRCUy9SIjogIlZZRGw0b1RlSjVUbUlQQ1hLZFRYMU1TV1JMSTlDS1ljeU1SejZ4bGFHZyIsCiAg
            ICAgICJEVEJTL1JIYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCiAgICB9CiAgXSwKICAicHJvY2Vzc0lEIjog
            ImVPWjZVd1h5ZUZMSzk4RG81MXgzM2ZtdXY0T3FBejVaYzRsc2hLTnRFZ1E9Igp9
        """.trimIndent()

        val transactionData = vckJsonSerializer.decodeFromString(
            Base64URLTransactionDataSerializer, vckJsonSerializer.encodeToString(input)
        )

        "Data classes are deserialized correctly" {
            transactionData.shouldBeInstanceOf<QesAuthorization>().apply {
                documentDigests.shouldNotBeEmpty().first().apply {
                    documentLocationMethod.shouldNotBeNull().apply {
                        documentAccessMode shouldBe DocumentLocationMethod.DocumentAccessMode.OTP
                        oneTimePassword shouldNotBe null
                    }
                }
            }
        }


        "Encoding-Decoding is correct" {
            val expected = vckJsonSerializer.decodeFromString<JsonElement>(
                input.decodeToByteArray(Base64UrlStrict).decodeToString()
            ).canonicalize() as JsonObject

            val actual = vckJsonSerializer.encodeToJsonElement(TransactionData.serializer(), transactionData)
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
        val input = """
            ewogICJ0eXBlIjogInFjZXJ0X2NyZWF0aW9uX2FjY2VwdGFuY2UiLAogICJjcmVkZW50aWFsX2lkcyI6IFtdLAogICJRQ190ZXJtc19jb25k
            aXRpb25zX3VyaSI6ICJodHRwczovL2V4YW1wbGUuY29tL3RvcyIsCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQytEK2I3
            T0NyRG84SU9HWmpTWDgvTT0iLAogICJRQ19oYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiCn0
        """.trimIndent()

        val parsed = vckJsonSerializer.decodeFromString(
            Base64URLTransactionDataSerializer, vckJsonSerializer.encodeToString(input)
        )

        "Data classes are deserialized correctly" {
            parsed.shouldBeInstanceOf<QCertCreationAcceptance>()
        }

        "Encoding-Decoding is correct" {
            val expected = vckJsonSerializer.decodeFromString<JsonElement>(
                input.decodeToByteArray(Base64UrlStrict).decodeToString()
            ).canonicalize()

            vckJsonSerializer.encodeToJsonElement(TransactionData.serializer(), parsed)
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
