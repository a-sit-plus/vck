package at.asitplus.openid

import at.asitplus.csc.bindings.QesApprovalDocument
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

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
            ),
        )

        json shouldBe """{"type":"${QesRequest.TYPE}","credential_ids":["certificate"],"signatureQualifier":"eu_eidas_qes","signatureRequests":[{"label":"Contract","href":"https://example.test/contract.pdf","responseURI":"https://example.test/signatures/1"}]}"""
        Json.decodeFromString<TransactionData>(json).shouldBeInstanceOf<QesRequest>()
    }

    test("qes approval request accepts documentInfo and documentReference") {
        val request = QesApprovalRequest(
            credentialIds = setOf("approval-credential"),
            numSignatures = 1,
            signatureQualifier = SignatureQualifier.EU_EIDAS_QES,
            documentDigests = listOf(
                QesApprovalDocument(documentInfo = DocumentInfo(label = "Contract", hash = byteArrayOf(1, 2, 3))),
                QesApprovalDocument(documentReference = DocumentReference(label = "Terms", href = "https://example.test/terms.pdf")),
            ),
            hashAlgorithmOid = ObjectIdentifier("2.16.840.1.101.3.4.2.1"),
        )

        val json = Json.encodeToString<TransactionData>(request)
        json shouldBe """{"type":"${QesApprovalRequest.TYPE}","credential_ids":["approval-credential"],"numSignatures":1,"signatureQualifier":"eu_eidas_qes","documentDigests":[{"label":"Contract","hash":"AQID"},{"label":"Terms","href":"https://example.test/terms.pdf"}],"hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"}"""
        val decoded = Json.decodeFromString<TransactionData>(json).shouldBeInstanceOf<QesApprovalRequest>()
        decoded.documentDigests.size shouldBe 2
        decoded.documentDigests[0].documentInfo?.label shouldBe "Contract"
        decoded.documentDigests[0].documentInfo?.hash?.contentEquals(byteArrayOf(1, 2, 3)) shouldBe true
        decoded.documentDigests[0].documentReference shouldBe null
        decoded.documentDigests[1].documentReference shouldBe request.documentDigests[1].documentReference
        decoded.documentDigests[1].documentInfo shouldBe null
    }

}
