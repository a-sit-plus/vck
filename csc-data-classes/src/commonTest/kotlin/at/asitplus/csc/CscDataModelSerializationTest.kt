package at.asitplus.csc

import at.asitplus.csc.datamodel.authorization.SignatureCreationApproval
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.ConformanceLevel
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.basic.SignedEnvelopeProperty
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.AccessControlMethod
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.csc.datamodel.documents.DocumentRepresentations
import at.asitplus.csc.datamodel.documents.DocumentType
import at.asitplus.csc.datamodel.documents.HashType
import at.asitplus.csc.datamodel.requests.SignatureCreationRequest
import at.asitplus.csc.datamodel.requests.SignatureRequest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

private val json = Json {
    encodeDefaults = false
    explicitNulls = false
}

private fun String.asJson() = Json.parseToJsonElement(this)

val CscDataModelSerializationTest by matrixSuite {
    test("CSC enumeration values use their specified wire names") {
        json.decodeFromString<SignatureQualifier>("\"eu_eidas_qes\"") shouldBe SignatureQualifier.EU_EIDAS_QES
        json.encodeToString(DocumentType.SFD) shouldBe "\"sfd\""
        json.decodeFromString<HashType>("\"dtbsr\"") shouldBe HashType.DTBSR
    }

    test("ETSI conformance levels use the Data Model 1.0 wire values") {
        json.encodeToString(ConformanceLevel.ADESLT) shouldBe "\"AdES-LT\""
        json.encodeToString(ConformanceLevel.ADESLTA) shouldBe "\"AdES-LTA\""
    }

    test("hash uses standard padded Base64 and has content equality") {
        val hash = Hash(byteArrayOf(1, 2, 3), ObjectIdentifier("2.16.840.1.101.3.4.2.1"))
        json.encodeToString(hash).asJson() shouldBe
                """{"value":"AQID","algorithmOID":"2.16.840.1.101.3.4.2.1"}""".asJson()
        json.decodeFromString<Hash>(json.encodeToString(hash)) shouldBe hash
        hash shouldBe hash.copy(value = byteArrayOf(1, 2, 3))
    }

    test("signatureCreationRequest flattens document data, AdES, and algorithm parameters") {
        val request = SignatureCreationRequest(
            document = DocumentData(label = "Contract", document = byteArrayOf(1, 2, 3)),
            adesParameters = AdesParameters(
                signatureFormat = SignatureFormat.PADES,
                conformanceLevel = ConformanceLevel.ADESBB,
                signedEnvelopeProperty = SignedEnvelopeProperty.CERTIFICATION,
            ),
            signingAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.10045.4.3.2")),
        )
        val encoded = json.encodeToString(request)
        encoded.asJson() shouldBe """{
            "label":"Contract",
            "document":"AQID",
            "signature_format":"P",
            "conformance_level":"AdES-B-B",
            "signed_envelope_property":"Certification",
            "signAlgo":"1.2.840.10045.4.3.2"
        }""".asJson()
        json.decodeFromString<SignatureCreationRequest>(encoded) shouldBe request
    }

    test("signatureCreationRequest supports flattened document representations") {
        val request = SignatureCreationRequest(
            document = DocumentRepresentations(label = "Contract", hashes = listOf(byteArrayOf(4, 5, 6))),
            signingAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.113549.1.1.1")),
        )
        val encoded = json.encodeToString(request)
        encoded.asJson() shouldBe """{
            "label":"Contract",
            "hashes":["BAUG"],
            "signAlgo":"1.2.840.113549.1.1.1"
        }""".asJson()
        json.decodeFromString<SignatureCreationRequest>(encoded) shouldBe request
    }

    test("signatureRequest flattens a document reference and uses responseURI") {
        val request = SignatureRequest(
            document = DocumentReference(
                label = "Contract",
                access = AccessControlMethod.Public,
                href = "https://example.com/contract.pdf",
            ),
            adesParameters = AdesParameters(signatureFormat = SignatureFormat.PADES),
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            responseUri = "https://example.com/signature",
        )
        val encoded = json.encodeToString(request)
        encoded.asJson() shouldBe """{
            "label":"Contract",
            "access":{"type":"public"},
            "href":"https://example.com/contract.pdf",
            "signature_format":"P",
            "signatureQualifier":"eu_eidas_qes",
            "responseURI":"https://example.com/signature"
        }""".asJson()
        json.decodeFromString<SignatureRequest>(encoded) shouldBe request
    }

    test("signatureCreationApproval uses canonical field names") {
        val approval = SignatureCreationApproval(
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            numSignatures = 1,
            documentDigests = listOf(DocumentInfo(label = "Contract", hash = byteArrayOf(7, 8, 9))),
            hashAlgorithmOid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
        )
        val encoded = json.encodeToString(approval)
        encoded.asJson() shouldBe """{
            "signatureQualifier":"eu_eidas_qes",
            "numSignatures":1,
            "documentDigests":[{"label":"Contract","hash":"BwgJ"}],
            "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
        }""".asJson()
        json.decodeFromString<SignatureCreationApproval>(encoded) shouldBe approval
    }
}
