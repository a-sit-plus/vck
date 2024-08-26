package at.asitplus.wallet.lib.data

import at.asitplus.jsonpath.JsonPath
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.dif.Base64URLTransactionDataSerializer
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.TransactionDataEntry
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
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
                        "ew0KICAidHlwZSI6ICJxZXNfYXV0aG9yaXphdGlvbiIsDQogICJzaWduYXR1cmVRdWFsaWZpZXIiOiAiZXVfZWlkYXNfcWVzIiwNCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUVyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsDQogICJkb2N1bWVudERpZ2VzdHMiOiBbDQogICAgew0KICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLA0KICAgICAgImhhc2giOiAic1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0iLA0KICAgICAgImhhc2hBbGdvcml0aG1PSUQiOiAiMi4xNi44NDAuMS4xMDEuMy40LjIuMSIsDQogICAgICAiZG9jdW1lbnRMb2NhdGlvbnNfdXJpIjogImh0dHBzOi8vcHJvdGVjdGVkLnJwLmV4YW1wbGUvY29udHJhY3QtMDEucGRmP3Rva2VuPUhTOW5hSktXd3A5MDFoQmNLmzQ4SVVIaXVIODM3NCIsDQogICAgICAiZG9jdW1lbnRMb2NhdGlvbl9tZXRob2QiOiB7DQogICAgICAgICJtZXRob2QiOiB7DQogICAgICAgICAgInR5cGUiOiAicHVibGljIg0KICAgICAgICB9DQogICAgICB9LA0KICAgICAgImR0YnNyIjogIlZZRGw0b1RlSjVUbUlQQ1hLZFRYMU1TV1JMSTlDS1ljeU1SejZ4bGFHZyIsDQogICAgICAiZHRic3JIYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiDQogICAgfQ0KICBdLA0KICAicHJvY2Vzc0lEIjogImVPWjZVd1h5ZUZMSzk4RG81MXgzM2ZtdXY0T3FBejVaYzRsc2hLTnRFZ1E9Ig0KfQ==",
                        "ew0KICAidHlwZSI6ICJxY2VydF9jcmVhdGlvbl9hY2NlcHRhbmNlIiwNCiAgIlFDX3Rlcm1zX2NvbmRpdGlvbnNfdXJpIjogImh0dHBzOi8vZXhhbXBsZS5jb20vdG9zIiwNCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQy1ELWI3T0NyRG84SU9HWmpTWDhfTT0iLA0KICAiUUNfaGFzaEFsZ29yaXRobU9JRCI6ICIyLjE2Ljg0MC4xLjEwMS4zLjQuMi4xIg0KfQ=="
                    ]
                }
            ]
        }
    """.trimIndent().replace("\n", "").replace("\r", "").replace(" ", "")

    val transactionDataTest = TransactionDataEntry.QCertCreationAcceptance(
        qcTermsConditionsUri = "abc",
        qcHash = "cde",
        qcHashAlgorithmOID = "fgh"
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
        val testVector = "ew0KICAidHlwZSI6ICJxZXNfYXV0aG9yaXphdGlvbiIsDQogICJzaWduYXR1cmVRdWFsaWZpZXIiOiAiZXVfZWlkYXNfcWVzIiwNCiAgImNyZWRlbnRpYWxJRCI6ICJvRW92QzJFSEZpRUVyRHBVeDhtUjBvN3llR0hrMmg3NGIzWHl3a05nQkdvPSIsDQogICJkb2N1bWVudERpZ2VzdHMiOiBbDQogICAgew0KICAgICAgImxhYmVsIjogIkV4YW1wbGUgQ29udHJhY3QiLA0KICAgICAgImhhc2giOiAic1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0iLA0KICAgICAgImhhc2hBbGdvcml0aG1PSUQiOiAiMi4xNi44NDAuMS4xMDEuMy40LjIuMSIsDQogICAgICAiZG9jdW1lbnRMb2NhdGlvbnNfdXJpIjogImh0dHBzOi8vcHJvdGVjdGVkLnJwLmV4YW1wbGUvY29udHJhY3QtMDEucGRmP3Rva2VuPUhTOW5hSktXd3A5MDFoQmNLmzQ4SVVIaXVIODM3NCIsDQogICAgICAiZG9jdW1lbnRMb2NhdGlvbl9tZXRob2QiOiB7DQogICAgICAgICJtZXRob2QiOiB7DQogICAgICAgICAgInR5cGUiOiAicHVibGljIg0KICAgICAgICB9DQogICAgICB9LA0KICAgICAgImR0YnNyIjogIlZZRGw0b1RlSjVUbUlQQ1hLZFRYMU1TV1JMSTlDS1ljeU1SejZ4bGFHZyIsDQogICAgICAiZHRic3JIYXNoQWxnb3JpdGhtT0lEIjogIjIuMTYuODQwLjEuMTAxLjMuNC4yLjEiDQogICAgfQ0KICBdLA0KICAicHJvY2Vzc0lEIjogImVPWjZVd1h5ZUZMSzk4RG81MXgzM2ZtdXY0T3FBejVaYzRsc2hLTnRFZ1E9Ig0KfQ=="
        val transactionData = runCatching { vckJsonSerializer.decodeFromString(Base64URLTransactionDataSerializer, vckJsonSerializer.encodeToString(testVector)) }.getOrNull()
        transactionData shouldNotBe null
        val expected = vckJsonSerializer.decodeFromString<JsonElement>(testVector.decodeToByteArray(Base64UrlStrict).decodeToString()).canonicalize()
        val actual = vckJsonSerializer.encodeToJsonElement(transactionData).canonicalize()
        actual shouldBe expected
    }

    "TransactionDataEntry.QCertCreationAcceptance can be parsed" {
        val testVector = "ew0KICAidHlwZSI6ICJxY2VydF9jcmVhdGlvbl9hY2NlcHRhbmNlIiwNCiAgIlFDX3Rlcm1zX2NvbmRpdGlvbnNfdXJpIjogImh0dHBzOi8vZXhhbXBsZS5jb20vdG9zIiwNCiAgIlFDX2hhc2giOiAia1hBZ3dEY2RBZTNvYnhwbzhVb0RrQy1ELWI3T0NyRG84SU9HWmpTWDhfTT0iLA0KICAiUUNfaGFzaEFsZ29yaXRobU9JRCI6ICIyLjE2Ljg0MC4xLjEwMS4zLjQuMi4xIg0KfQ=="
        val transactionData = runCatching { vckJsonSerializer.decodeFromString(Base64URLTransactionDataSerializer, vckJsonSerializer.encodeToString(testVector)) }.getOrNull()
        transactionData shouldNotBe null
        val expected = vckJsonSerializer.decodeFromString<JsonElement>(testVector.decodeToByteArray(Base64UrlStrict).decodeToString()).canonicalize()
        val actual = vckJsonSerializer.encodeToJsonElement(transactionData).canonicalize()
        actual shouldBe expected
    }

    "The presentation Definition can be parsed" {
        val presentationDefinition = runCatching { vckJsonSerializer.decodeFromString<PresentationDefinition>(presentationDefinitionAsJsonString) }.getOrNull()
        Napier.d(presentationDefinition.toString())
        presentationDefinition shouldNotBe null
        presentationDefinition?.inputDescriptors?.first()?.transactionData shouldNotBe null
    }
})


fun JsonElement.canonicalize(): JsonElement =
    when (this) {
        is JsonObject -> JsonObject(this.entries.sortedBy { it.key }.associate { it.key to it.value.canonicalize() })
        is JsonArray -> JsonArray(this.map { it.canonicalize() }.sortedBy { vckJsonSerializer.encodeToString(it) })
        is JsonPrimitive -> this
        JsonNull -> this
    }
