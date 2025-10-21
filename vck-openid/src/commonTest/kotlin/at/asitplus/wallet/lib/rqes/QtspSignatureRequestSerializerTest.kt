package at.asitplus.wallet.lib.rqes

import at.asitplus.csc.QtspSignatureRequest
import at.asitplus.csc.SignDocRequestParameters
import at.asitplus.csc.SignHashRequestParameters
import at.asitplus.csc.collection_entries.Document
import at.asitplus.csc.collection_entries.DocumentDigest
import at.asitplus.csc.enums.ConformanceLevel
import at.asitplus.csc.enums.SignatureFormat
import at.asitplus.csc.enums.SignedEnvelopeProperty
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
import at.asitplus.testballoon.*
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement

val QtspSignatureRequestSerializerTest by testSuite{

    val adaptedCscTestVectorSignHash1 = """
    {
        "credentialID":"GX0112348",
        "SAD":"_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "hashes":[
            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
        ],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "signAlgo":"1.2.840.113549.1.1.11",
        "clientData":"12345678"
    }""".trimIndent()

    val adaptedCscTestVectorSignHash2 = """
    {
        "credentialID":"GX0112348",
        "SAD":"_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "hashes":[
            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
        ],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "signAlgo":"1.2.840.113549.1.1.11",
        "operationMode": "A",
        "clientData":"12345678"
    }""".trimIndent()

    val adaptedCscTestVectorSignHash3 = """
    {
        "credentialID":"GX0112348",
        "hashes":[
            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "c1RPZ3dPbSs0NzRnRmowcTB4MWlTTnNwS3FiY3NlNEllaXFsRGcvSFd1ST0="
        ],
        "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1",
        "signAlgo":"1.2.840.113549.1.1.11",
        "operationMode": "A",
        "clientData":"12345678"
    }""".trimIndent()

    val adaptedCscTestVectorSignDoc1 = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documentDigests": [
            {
                "hashes": ["sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.11"
            },
            {
                "hashes": ["HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "C",
                "signAlgo": "1.2.840.113549.1.1.11"
            }
        ],
        "clientData": "12345678"
    }""".trimIndent()

    val adaptedCscTestVectorSignDoc2 = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documents": [
            {
                "document": "UTJWeWRHbG1hV05oZEdWVFpYSnBZV3hPZFcxaVrigKZLekJUV1dWSldXWlpWWHB0VTNWNU1WVTlEUW89",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.11"
            },
            {
                "document": "UTJWeWRHbG1hV05oZEdWVFpYSnBZV3hPZFcxaVrigKZLekJUV1dWSldXWlpWWHB0VTNWNU1WVTlEUW89",
                "signature_format": "C",
                "signAlgo": "1.2.840.113549.1.1.11"
            }
        ],
        "clientData": "12345678"
    }""".trimIndent()

    val adaptedCscTestVectorSignDoc3 = """
    {
        "credentialID": "GX0112348",
        "SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24/CKN69L8gdSYp5_pw",
        "documentDigests": [
            {
                "hashes": ["sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.11"
            },
            {
                "hashes": ["HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="],
                "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
                "signature_format": "C",
                "signAlgo": "1.2.840.113549.1.1.11"
            }
        ],
        "documents": [
            {
                "document": "UTJWeWRHbG1hV05oZEdWVFpYSnBZV3hPZFcxaVrigKZLekJUV1dWSldXWlpWWHB0VTNWNU1WVTlEUW89",
                "signature_format": "P",
                "conformance_level": "AdES-B-T",
                "signAlgo": "1.2.840.113549.1.1.11"
            },
            {
                "document": "UTJWeWRHbG1hV05oZEdWVFpYSnBZV3hPZFcxaVrigKZLekJUV1dWSldXWlpWWHB0VTNWNU1WVTlEUW89",
                "signature_format": "C",
                "signAlgo": "1.2.840.113549.1.1.11"
            }
        ],
        "clientData": "12345678"
    }""".trimIndent()

    "SignatureRequestParameters can be serialized/deserialized" - {
        val dummyEntries =
            listOf(
                SignHashRequestParameters(
                    credentialId = "1234",
                    hashes = listOf("abcd".decodeToByteArray(Base64Strict)),
                    signAlgoOid = X509SignatureAlgorithm.ES256.oid
                ),
                SignDocRequestParameters(
                    credentialId = "1234",
                    documents = listOf(
                        Document(
                            document = "1234".decodeToByteArray(Base64Strict),
                            signatureFormat = SignatureFormat.JADES,
                            conformanceLevel = ConformanceLevel.ADESBLTA,
                            signAlgoOid = X509SignatureAlgorithm.ES256.oid,
                            signAlgoParams = null,
                            signedProps = null,
                            signedEnvelopeProperty = null
                        ),
                        Document(
                            document = "1234".decodeToByteArray(Base64Strict),
                            signatureFormat = SignatureFormat.CADES,
                            conformanceLevel = ConformanceLevel.ADEST,
                            signAlgoOid = X509SignatureAlgorithm.RS256.oid,
                            signAlgoParams = null,
                            signedProps = null,
                            signedEnvelopeProperty = SignedEnvelopeProperty.PARALLEL
                        ),
                    )
                ),
                SignDocRequestParameters(
                    credentialId = "1234",
                    documentDigests = listOf(
                        DocumentDigest(
                            hashes = listOf("1234".decodeToByteArray(Base64Strict)),
                            hashAlgorithmOid = Digest.SHA256.oid,
                            signatureFormat = SignatureFormat.XADES,
                            conformanceLevel = ConformanceLevel.ADESB,
                            signAlgoOid = X509SignatureAlgorithm.ES384.oid,
                            signAlgoParams = null,
                            signedProps = null,
                            signedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPING
                        ),
                        DocumentDigest(
                            hashes = listOf("1234".decodeToByteArray(Base64Strict)),
                            hashAlgorithmOid = null,
                            signatureFormat = SignatureFormat.PADES,
                            conformanceLevel = ConformanceLevel.ADESTLT,
                            signAlgoOid = X509SignatureAlgorithm.RS512.oid,
                            signAlgoParams = null,
                            signedProps = null,
                            signedEnvelopeProperty = SignedEnvelopeProperty.ENVELOPING
                        )
                    )
                )
            )
        dummyEntries.forEachIndexed { i, dummyEntry ->
            "Entry ${i + 1}" {
                val serialized = vckJsonSerializer.encodeToString(QtspSignatureRequest.serializer(), dummyEntry)
                    .also { Napier.d("serialized ${dummyEntry::class}: $it") }
                val deserialized =
                    vckJsonSerializer.decodeFromString(QtspSignatureRequest.serializer(), serialized)

                deserialized shouldBe dummyEntry
            }
        }
    }

    "CSC Test vectors" - {
        listOf(
            adaptedCscTestVectorSignHash1,
            adaptedCscTestVectorSignHash2,
            adaptedCscTestVectorSignHash3,
            adaptedCscTestVectorSignDoc1,
            adaptedCscTestVectorSignDoc2,
            adaptedCscTestVectorSignDoc3
        ).forEachIndexed { i, vec ->
            "Testvector ${i + 1}" {
                val expected = vckJsonSerializer.decodeFromString<JsonObject>(vec).canonicalize()
                val actual = vckJsonSerializer.encodeToJsonElement(
                    vckJsonSerializer.decodeFromString(QtspSignatureRequest.serializer(), vec)
                ).canonicalize()

                actual shouldBe expected
            }
        }
    }
}