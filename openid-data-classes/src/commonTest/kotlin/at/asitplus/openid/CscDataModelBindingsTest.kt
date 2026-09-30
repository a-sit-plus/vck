package at.asitplus.openid

import at.asitplus.csc.bindings.QesApprovalDocument
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.ConformanceLevel
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.basic.SignedEnvelopeProperty
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.AccessControlMethod
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json

/** CSC Data Model Bindings v1.0.0 Sec. 6.2.1.2 */
private val testvec: String = """{
    "type":"https://cloudsignatureconsortium.org/2025/qes",
    "credential_ids":["xyz123"],
    "signatureQualifier":"eu_eidas_qes",
    "signatureRequests":[
        {
            "label":"Example Contract",
            "access":{"type":"OTP","oneTimePassword":"51623"},
            "href":"https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBkC34BIUHuH8374",
            "checksum":"sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI",
            "signature_format":"P",
            "conformance_level":"AdES-B-B",
            "signed_envelope_property":"Certification",
            "signAlgo":"1.2.840.113549.1.1.1"
        },
        {
            "label":"Example Terms of Service",
            "access":{"type":"public"},
            "href":"https://public.rp-cdn.example/terms-and-conditions.pdf",
            "checksum":"sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0",
            "signature_format":"P",
            "conformance_level":"AdES-B-B",
            "signed_envelope_property":"Certification",
            "signAlgo":"1.2.840.113549.1.1.1"
        },
        {
            "label":"Example Configuration",
            "href":"data:application/json;base64,eyJleGFtcGxlS2V5IjoiaXhhbXBsZSJ9",
            "signature_format":"J",
            "conformance_level":"AdES-B-B",
            "signed_envelope_property":"Attached",
            "signAlgo":"1.2.840.113549.1.1.1"
        }
    ]
}""".trimIndent()


private fun checksumFromIntegrityString(value: String): Hash = Json.decodeFromString(
    """{"value":"${value.substringAfter('-')}","algorithmOID":"2.16.840.1.101.3.4.2.1"}""",
)

val CscDataModelBindingsTest by matrixSuite {
    test("qes request uses its binding type and flattened CSC signature requests") {
        val json = Json.encodeToString<TransactionData>(
            QesRequest(
                credentialIds = setOf("certificate"),
                signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
                signatureRequests = listOf(
                    QesSignatureRequest(
                        document = DocumentReference(label = "Contract", href = "https://example.test/contract.pdf"),
                        responseUri = "https://example.test/signatures/1",
                    ),
                ),
                transactionDataHashAlgorithms = setOf("sha-384"),
            ),
        )

        json shouldBe """{"type":"${QesRequest.TYPE}","credential_ids":["certificate"],"signatureQualifier":"eu_eidas_qes","signatureRequests":[{"label":"Contract","href":"https://example.test/contract.pdf","responseURI":"https://example.test/signatures/1"}],"transaction_data_hashes_alg":["sha-384"]}"""
        Json.decodeFromString<TransactionData>(json).shouldBeInstanceOf<QesRequest>()
            .transactionDataHashAlgorithms shouldBe setOf("sha-384")
    }

    test("TS 119 432 Annex A transaction request example round-trips") {
        val signatureAlgorithm = SigningAlgorithm(ObjectIdentifier("1.2.840.113549.1.1.1"))
        val request = QesRequest(
            credentialIds = setOf("xyz123"),
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            signatureRequests = listOf(
                QesSignatureRequest(
                    document = DocumentReference(
                        label = "Example Contract",
                        access = AccessControlMethod.OTP("51623"),
                        href = "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBkC34BIUHuH8374",
                        checksum = checksumFromIntegrityString("sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI"),
                    ),
                    adesParameters = AdesParameters(
                        signatureFormat = SignatureFormat.PADES,
                        conformanceLevel = ConformanceLevel.ADESBB,
                        signedEnvelopeProperty = SignedEnvelopeProperty.CERTIFICATION,
                    ),
                    signingAlgorithm = signatureAlgorithm,
                ),
                QesSignatureRequest(
                    document = DocumentReference(
                        label = "Example Terms of Service",
                        access = AccessControlMethod.Public,
                        href = "https://public.rp-cdn.example/terms-and-conditions.pdf",
                        checksum = checksumFromIntegrityString("sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0"),
                    ),
                    adesParameters = AdesParameters(
                        signatureFormat = SignatureFormat.PADES,
                        conformanceLevel = ConformanceLevel.ADESBB,
                        signedEnvelopeProperty = SignedEnvelopeProperty.CERTIFICATION,
                    ),
                    signingAlgorithm = signatureAlgorithm,
                ),
                QesSignatureRequest(
                    document = DocumentReference(
                        label = "Example Configuration",
                        href = "data:application/json;base64,eyJleGFtcGxlS2V5IjoiaXhhbXBsZSJ9",
                    ),
                    adesParameters = AdesParameters(
                        signatureFormat = SignatureFormat.JADES,
                        conformanceLevel = ConformanceLevel.ADESBB,
                        signedEnvelopeProperty = SignedEnvelopeProperty.ATTACHED,
                    ),
                    signingAlgorithm = signatureAlgorithm,
                ),
            ),
        )
        val encoded = Json.encodeToString<TransactionData>(request)
        Json.parseToJsonElement(encoded) shouldBe Json.parseToJsonElement(testvec)
        val decoded = Json.decodeFromString<TransactionData>(encoded).shouldBeInstanceOf<QesRequest>()

        decoded.signatureRequests.size shouldBe 3
        decoded.signatureRequests[0].signingAlgorithm shouldBe signatureAlgorithm
        decoded.signatureRequests[0].document.shouldBeInstanceOf<DocumentReference>().checksum?.digest shouldBe
                Digest.SHA256
        decoded.signatureRequests[0].document.shouldBeInstanceOf<DocumentReference>().access shouldBe
                AccessControlMethod.OTP("51623")
        decoded.signatureRequests[2].document.shouldBeInstanceOf<DocumentReference>().href shouldBe
                "data:application/json;base64,eyJleGFtcGxlS2V5IjoiaXhhbXBsZSJ9"
    }

    test("qes approval request accepts documentInfo and documentReference") {
        val request = QesApprovalRequest(
            credentialIds = setOf("approval-credential"),
            numSignatures = 1,
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            documentDigests = listOf(
                QesApprovalDocument(documentInfo = DocumentInfo(label = "Contract", hash = byteArrayOf(1, 2, 3))),
                QesApprovalDocument(
                    documentReference = DocumentReference(
                        label = "Terms",
                        href = "https://example.test/terms.pdf"
                    )
                ),
            ),
            hashAlgorithmOid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
            transactionDataHashAlgorithms = setOf("sha-384"),
        )

        val json = Json.encodeToString<TransactionData>(request)
        json shouldBe """{"type":"${QesApprovalRequest.TYPE}","credential_ids":["approval-credential"],"numSignatures":1,"signatureQualifier":"eu_eidas_qes","documentDigests":[{"label":"Contract","hash":"AQID"},{"label":"Terms","href":"https://example.test/terms.pdf"}],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.1","transaction_data_hashes_alg":["sha-384"]}"""
        val decoded = Json.decodeFromString<TransactionData>(json).shouldBeInstanceOf<QesApprovalRequest>()
        decoded.transactionDataHashAlgorithms shouldBe setOf("sha-384")
        decoded.documentDigests.size shouldBe 2
        decoded.documentDigests[0].documentInfo?.label shouldBe "Contract"
        decoded.documentDigests[0].documentInfo?.hash?.contentEquals(byteArrayOf(1, 2, 3)) shouldBe true
        decoded.documentDigests[0].documentReference shouldBe null
        decoded.documentDigests[1].documentReference shouldBe request.documentDigests[1].documentReference
        decoded.documentDigests[1].documentInfo shouldBe null
    }

}
