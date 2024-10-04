package at.asitplus.dif

import at.asitplus.dif.rqes.CSCSignatureRequestParameters
import at.asitplus.dif.rqes.SignDocParameters
import at.asitplus.dif.rqes.SignHashParameters
import at.asitplus.signum.indispensable.io.Base64Strict
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement

class AuthenticationRequestParameterFromSerializerTest : FreeSpec({

    val cscTestVectorSignHash1 = """
    {
        "credentialID":"GX0112348",
        "SAD":"_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "hashes":[
            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
        ],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "signAlgo":"1.2.840.113549.1.1.1",
        "clientData":"12345678"
    }""".trimIndent()

    val cscTestVectorSignHash2 = """
    {
        "credentialID":"GX0112348",
        "SAD":"_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "hashes":[
            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
        ],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "signAlgo":"1.2.840.113549.1.1.1",
        "operationMode": "A",
        "clientData":"12345678"
    }""".trimIndent()

    val cscTestVectorSignHash3 = """
    {
        "credentialID":"GX0112348",
        "hashes":[
            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
        ],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "signAlgo":"1.2.840.113549.1.1.1",
        "operationMode": "A",
        "clientData":"12345678"
    }""".trimIndent()

    val cscTestVectorSignDoc1 = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documentDigests": [
            {
                "hashes": ["sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.1"
            },
            {
                "hashes": ["HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "C",
                "conformance_level": "AdES-B-B",
                "signAlgo": "1.2.840.113549.1.1.1"
            }
        ],
        "clientData": "12345678"
    }""".trimIndent()

    val cscTestVectorSignDoc2 = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documents": [
            {
                "document": "Q2VydGlmaWNhdGVTZXJpYWxOdW1iZ…KzBTWWVJWWZZVXptU3V5MVU9DQo=",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.1"
            },
            {
                "document": "Q2VydGlmaWNhdGVTZXJpYWxOdW1iZXI7U3… emNNbUNiL1cyQT09DQo=",
                "signature_format": "C",
                "conformance_level": "AdES-B-B",
                "signed_envelope_property": "Attached",
                "signAlgo": "1.2.840.113549.1.1.1"
            }
        ],
        "clientData": "12345678"
    }""".trimIndent()

    val cscTestVectorSignDoc3 = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documentDigests": [
            {
                "hashes": ["sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.1"
            },
            {
                "hashes": ["HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "C",
                "conformance_level": "AdES-B-B",
                "signAlgo": "1.2.840.113549.1.1.1"
            }
        ],
        "documents": [
            {
                "document": "Q2VydGlmaWNhdGVTZXJpYWxOdW1iZ…KzBTWWVJWWZZVXptU3V5MVU9DQo=",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.1"
            },
            {
                "document": "Q2VydGlmaWNhdGVTZXJpYWxOdW1iZXI7U3… emNNbUNiL1cyQT09DQo=",
                "signature_format": "C",
                "conformance_level": "AdES-B-B",
                "signed_envelope_property": "Attached",
                "signAlgo": "1.2.840.113549.1.1.1"
            }
        ],
        "clientData": "12345678"
    }""".trimIndent()

    "SignatureRequestParameters can be serialized/deserialized" - {
        val dummyEntries =
            listOf(
                SignHashParameters(
                    credentialId = "1234",
                    hashes = listOf("abcd".decodeToByteArray(Base64Strict)),
                ),
                SignDocParameters(
                    credentialId = "1234",
                    documents = listOf() //TODO add documents
                ),
                SignDocParameters(
                    credentialId = "1234",
                    documentDigests = listOf() //TODO add documentdigest
                )
            )
        dummyEntries.forEachIndexed { i, dummyEntry ->
            "Entry ${i + 1}" {
                val serialized = jsonSerializer.encodeToString(CSCSignatureRequestParameters.serializer(), dummyEntry)
                    .also { Napier.d("serialized ${dummyEntry::class}: $it") }
                val deserialized =
                    jsonSerializer.decodeFromString(CSCSignatureRequestParameters.serializer(), serialized)

                deserialized shouldBe dummyEntry
            }
        }
    }

    //TODO fix asn1 parsing
    "CSC Test vectors".config(enabled = false) - {
        listOf(
            cscTestVectorSignHash1,
            cscTestVectorSignHash2,
            cscTestVectorSignHash3,
            cscTestVectorSignDoc1,
            cscTestVectorSignDoc2,
            cscTestVectorSignDoc3
        ).forEachIndexed { i, vec ->
            "Testvector ${i + 1}" - {
                val expected = jsonSerializer.decodeFromString<JsonObject>(vec)
                val actual = jsonSerializer.decodeFromString(CSCSignatureRequestParameters.serializer(), vec)
                val sanitycheck =
                    jsonSerializer.decodeFromJsonElement(CSCSignatureRequestParameters.serializer(), expected)
                "sanitycheck" {
                    actual shouldBe sanitycheck
                }

                "actual test".config(enabled = true) {
                    val test1 = jsonSerializer.encodeToJsonElement(actual).canonicalize()
                    val test2 = expected.canonicalize()
                    test1 shouldBe test2
//                    jsonSerializer.encodeToJsonElement(actual).canonicalize() shouldBe expected.canonicalize()
                }
            }
        }
    }
})