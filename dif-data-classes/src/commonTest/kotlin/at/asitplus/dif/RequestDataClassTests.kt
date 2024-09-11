package at.asitplus.dif

import at.asitplus.dif.rqes.SignatureRequestParameters
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
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

    val cscTestVectorSignDoc = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documentDigests": [
            {
                "hashes": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.1"
            },
            {
                "hashes": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
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

    "signHash Test vectors" -  {
        "Testvector 1" {
            val expected = jsonSerializer.decodeFromString<JsonObject>(cscTestVectorSignHash1).canonicalize()
            val actual = jsonSerializer.decodeFromString(SignatureRequestParameters.serializer(), cscTestVectorSignHash1)
            jsonSerializer.encodeToJsonElement(actual).canonicalize() shouldBe expected
        }
        "Testvector 2" {
            val expected = jsonSerializer.decodeFromString<JsonObject>(cscTestVectorSignHash2).canonicalize()
            val actual = jsonSerializer.decodeFromString(SignatureRequestParameters.serializer(), cscTestVectorSignHash2)
            jsonSerializer.encodeToJsonElement(actual).canonicalize() shouldBe expected
        }
        "Testvector 3" {
            val expected = jsonSerializer.decodeFromString<JsonObject>(cscTestVectorSignHash3).canonicalize()
            val actual = jsonSerializer.decodeFromString(SignatureRequestParameters.serializer(), cscTestVectorSignHash3)
            jsonSerializer.encodeToJsonElement(actual).canonicalize() shouldBe expected
        }
    }
})