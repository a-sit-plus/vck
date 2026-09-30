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
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

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


@OptIn(ExperimentalEncodingApi::class)
private fun sha256Hash(base64: String) = Hash(
    value = Base64.Default.decode(
        base64.padEnd(
            base64.length + (4 - base64.length % 4) % 4,
            '='
        )
    ),
    algorithmOid = Digest.SHA256.oid,
)

val CscDataModelBindingsTest by matrixSuite {

    test("qes request uses its binding type and flattened CSC signature requests") {
        val json = Json.encodeToString<TransactionData>(
            QesRequest(
                credentialIds = setOf("certificate"),
                signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
                signatureRequests = listOf(
                    QesSignatureRequest(
                        document = DocumentReference(
                            label = "Contract",
                            href = "https://example.test/contract.pdf",
                        ),
                        responseUri = "https://example.test/signatures/1",
                    ),
                ),
                transactionDataHashAlgorithms = setOf("sha-384"),
            ),
        )

        json shouldBe """{"type":"${QesRequest.TYPE}","credential_ids":["certificate"],"signatureQualifier":"eu_eidas_qes","signatureRequests":[{"label":"Contract","href":"https://example.test/contract.pdf","responseURI":"https://example.test/signatures/1"}],"transaction_data_hashes_alg":["sha-384"]}"""

        Json.decodeFromString<TransactionData>(json)
            .shouldBeInstanceOf<QesRequest>()
            .transactionDataHashAlgorithms shouldBe setOf("sha-384")
    }

    test("CSC Data Model Bindings 1.0.0 §6.2.1.2 transaction authorization request") {
        val signatureAlgorithm = SigningAlgorithm(
            ObjectIdentifier("1.2.840.113549.1.1.1")
        )

        val expected = QesRequest(
            credentialIds = setOf("xyz123"),
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            signatureRequests = listOf(
                QesSignatureRequest(
                    document = DocumentReference(
                        label = "Example Contract",
                        access = AccessControlMethod.OTP("51623"),
                        href = "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBkC34BIUHuH8374",
                        checksum = sha256Hash(
                            "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI"
                        ),
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
                        checksum = sha256Hash(
                            "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0"
                        ),
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

        Json.parseToJsonElement(
            Json.encodeToString<TransactionData>(expected)
        ) shouldBe Json.parseToJsonElement(testvec)

        val decoded = Json.decodeFromString<TransactionData>(testvec)
            .shouldBeInstanceOf<QesRequest>()

        decoded shouldBe expected

        val contract = decoded.signatureRequests[0].document
            .shouldBeInstanceOf<DocumentReference>()

        contract.checksum?.digest shouldBe Digest.SHA256
        contract.checksum?.value?.size shouldBe 32
        contract.access shouldBe AccessControlMethod.OTP("51623")

        val terms = decoded.signatureRequests[1].document
            .shouldBeInstanceOf<DocumentReference>()

        terms.checksum?.digest shouldBe Digest.SHA256
        terms.checksum?.value?.size shouldBe 32
        terms.access shouldBe AccessControlMethod.Public
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
