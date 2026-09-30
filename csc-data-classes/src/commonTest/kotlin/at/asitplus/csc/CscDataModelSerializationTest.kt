package at.asitplus.csc

import at.asitplus.csc.datamodel.authorization.SignatureCreationApproval
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.Attribute
import at.asitplus.csc.datamodel.basic.AttributeName
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
import at.asitplus.csc.datamodel.requests.SignatureCreationRequest
import at.asitplus.csc.datamodel.requests.SignatureRequest
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.Asn1Null
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.Json

private val json = Json {
    encodeDefaults = false
    explicitNulls = false
}

private fun String.asJson() = Json.parseToJsonElement(this)

private inline fun <reified T> T.shouldRoundTripAs(expected: String) {
    val encoded = json.encodeToString(this)
    encoded.asJson() shouldBe expected.asJson()
    json.decodeFromString<T>(encoded) shouldBe this
}

val CscDataModelSerializationTest by matrixSuite {
    test("corrected ETSI conformance levels use the Data Model 1.0 wire values") {
        json.encodeToString(ConformanceLevel.ADESLT) shouldBe "\"AdES-LT\""
        json.encodeToString(ConformanceLevel.ADESLTA) shouldBe "\"AdES-LTA\""
    }

    test("algorithm value objects preserve Base64, OIDs, parameters, and conversions") {
        val hash = Hash(byteArrayOf(1, 2, 3), ObjectIdentifier("2.16.840.1.101.3.4.2.1"))
        hash.shouldRoundTripAs("""{"value":"AQID","algorithmOID":"2.16.840.1.101.3.4.2.1"}""")
        hash.digest shouldBe Digest.SHA256

        val algorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.10045.4.3.2"))
        algorithm.toSignatureAlgorithmOrNull() shouldNotBe null

        val withParameters = SigningAlgorithm(ObjectIdentifier("1.2.3.4"), Asn1Null)
        withParameters.shouldRoundTripAs("""{"signAlgo":"1.2.3.4","signAlgoParams":"BQA="}""")
    }

    test("byte-array data models use content equality and matching hash codes") {
        fun assertContentEquality(first: Any, equal: Any, different: Any) {
            first shouldBe equal
            first.hashCode() shouldBe equal.hashCode()
            first shouldNotBe different
        }

        assertContentEquality(
            Hash(byteArrayOf(1, 2), ObjectIdentifier("2.16.840.1.101.3.4.2.1")),
            Hash(byteArrayOf(1, 2), ObjectIdentifier("2.16.840.1.101.3.4.2.1")),
            Hash(byteArrayOf(1, 3), ObjectIdentifier("2.16.840.1.101.3.4.2.1")),
        )
        assertContentEquality(
            DocumentData(document = byteArrayOf(1, 2), circumstantialData = byteArrayOf(3)),
            DocumentData(document = byteArrayOf(1, 2), circumstantialData = byteArrayOf(3)),
            DocumentData(document = byteArrayOf(1, 3), circumstantialData = byteArrayOf(3)),
        )
        assertContentEquality(
            DocumentInfo(hash = byteArrayOf(1, 2), circumstantialData = byteArrayOf(3)),
            DocumentInfo(hash = byteArrayOf(1, 2), circumstantialData = byteArrayOf(3)),
            DocumentInfo(hash = byteArrayOf(1, 3), circumstantialData = byteArrayOf(3)),
        )
        assertContentEquality(
            DocumentReference(href = "https://example.com", circumstantialData = byteArrayOf(1, 2)),
            DocumentReference(href = "https://example.com", circumstantialData = byteArrayOf(1, 2)),
            DocumentReference(href = "https://example.com", circumstantialData = byteArrayOf(1, 3)),
        )
        assertContentEquality(
            DocumentRepresentations(hashes = listOf(byteArrayOf(1), byteArrayOf(2))),
            DocumentRepresentations(hashes = listOf(byteArrayOf(1), byteArrayOf(2))),
            DocumentRepresentations(hashes = listOf(byteArrayOf(1), byteArrayOf(3))),
        )
    }

    test("signatureCreationRequest flattens document data") {
        SignatureCreationRequest(
            document = DocumentData(label = "Contract", document = byteArrayOf(1, 2, 3)),
            adesParameters = AdesParameters(
                signatureFormat = SignatureFormat.PADES,
                conformanceLevel = ConformanceLevel.ADESBB,
                signedEnvelopeProperty = SignedEnvelopeProperty.CERTIFICATION,
            ),
            signingAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.10045.4.3.2")),
        ).shouldRoundTripAs(
            """{
                "label":"Contract",
                "document":"AQID",
                "signature_format":"P",
                "conformance_level":"AdES-B-B",
                "signed_envelope_property":"Certification",
                "signAlgo":"1.2.840.10045.4.3.2"
            }""",
        )
    }

    test("signatureCreationRequest flattens document representations") {
        SignatureCreationRequest(
            document = DocumentRepresentations(label = "Contract", hashes = listOf(byteArrayOf(4, 5, 6))),
            signingAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.113549.1.1.1")),
        ).shouldRoundTripAs(
            """{
                "label":"Contract",
                "hashes":["BAUG"],
                "signAlgo":"1.2.840.113549.1.1.1"
            }""",
        )
    }

    test("signatureCreationRequest flattens document references") {
        SignatureCreationRequest(
            document = DocumentReference(
                label = "Contract",
                access = AccessControlMethod.Public,
                href = "https://example.com/contract.pdf",
                checksum = Hash(
                    value = byteArrayOf(7, 8, 9),
                    algorithmOid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
                ),
            ),
            adesParameters = AdesParameters(signatureFormat = SignatureFormat.PADES),
            signingAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.10045.4.3.2")),
        ).shouldRoundTripAs(
            """{
                "label":"Contract",
                "access":{"type":"public"},
                "href":"https://example.com/contract.pdf",
                "checksum":"sha256-BwgJ",
                "signature_format":"P",
                "signAlgo":"1.2.840.10045.4.3.2"
            }""",
        )
    }

    test("signatureRequest flattens document references and preserves responseURI") {
        SignatureRequest(
            document = DocumentReference(
                label = "Contract",
                access = AccessControlMethod.Public,
                href = "https://example.com/contract.pdf",
            ),
            adesParameters = AdesParameters(signatureFormat = SignatureFormat.PADES),
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            responseUri = "https://example.com/signature",
        ).shouldRoundTripAs(
            """{
                "label":"Contract",
                "access":{"type":"public"},
                "href":"https://example.com/contract.pdf",
                "signature_format":"P",
                "signatureQualifier":"eu_eidas_qes",
                "responseURI":"https://example.com/signature"
            }""",
        )
    }

    test("signatureRequest flattens document data with optional AdES fields") {
        SignatureRequest(
            document = DocumentData(
                label = "Contract",
                document = byteArrayOf(1, 2, 3),
                documentType = DocumentType.SFD,
            ),
            adesParameters = AdesParameters(
                signatureFormat = SignatureFormat.JADES,
                conformanceLevel = ConformanceLevel.ADESBT,
                signedEnvelopeProperty = SignedEnvelopeProperty.DETACHED,
                signedProps = listOf(Attribute(AttributeName.SIGNING_TIME, "2026-09-29T12:00:00Z")),
                referenceUri = "https://example.com/contract.json",
            ),
            signatureQualifier = SignatureQualifier.EU_EIDAS_AES,
        ).shouldRoundTripAs(
            """{
                "label":"Contract",
                "document":"AQID",
                "documentType":"sfd",
                "signature_format":"J",
                "conformance_level":"AdES-B-T",
                "signed_envelope_property":"Detached",
                "signed_props":[{"attribute_name":"signing-time","attribute_value":"2026-09-29T12:00:00Z"}],
                "referenceUri":"https://example.com/contract.json",
                "signatureQualifier":"eu_eidas_aes"
            }""",
        )
    }

    test("signatureCreationApproval supports either credential identification path") {
        val byQualifier = SignatureCreationApproval(
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            numSignatures = 1,
            documentDigests = listOf(DocumentInfo(label = "Contract", hash = byteArrayOf(7, 8, 9))),
            hashAlgorithmOid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
        )
        byQualifier.shouldRoundTripAs(
            """{
                "signatureQualifier":"eu_eidas_qes",
                "numSignatures":1,
                "documentDigests":[{"label":"Contract","hash":"BwgJ"}],
                "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
            }""",
        )

        byQualifier.copy(credentialId = "credential-1", signatureQualifier = null).shouldRoundTripAs(
            """{
                "credentialID":"credential-1",
                "numSignatures":1,
                "documentDigests":[{"label":"Contract","hash":"BwgJ"}],
                "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
            }""",
        )
    }
}
