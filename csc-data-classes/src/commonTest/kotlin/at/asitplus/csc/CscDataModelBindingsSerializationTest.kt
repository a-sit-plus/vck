package at.asitplus.csc

import at.asitplus.csc.bindings.QesApprovalBinding
import at.asitplus.csc.bindings.QesApprovalDocument
import at.asitplus.csc.bindings.QesResponse
import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.bindings.X509KeyInfo
import at.asitplus.csc.bindings.X509MetadataQuery
import at.asitplus.csc.bindings.X509PresentationResponse
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

private val bindingJson = Json {
    encodeDefaults = false
    explicitNulls = false
}

private inline fun <reified T> T.shouldRoundTripAs(expected: String) {
    val encoded = bindingJson.encodeToString(this)
    Json.parseToJsonElement(encoded) shouldBe Json.parseToJsonElement(expected)
    bindingJson.decodeFromString<T>(encoded) shouldBe this
}

val CscDataModelBindingsSerializationTest by matrixSuite {
    test("qes signature request flattens document reference and AdES fields") {
        QesSignatureRequest(
            document = DocumentReference(
                label = "Contract",
                href = "https://example.test/contract.pdf",
            ),
            adesParameters = AdesParameters(signatureFormat = SignatureFormat.PADES),
            responseUri = "https://example.test/signatures/1",
            checksum = Hash(byteArrayOf(7, 8, 9), ObjectIdentifier("2.16.840.1.101.3.4.2.1")),
        ).shouldRoundTripAs(
            """{"label":"Contract","href":"https://example.test/contract.pdf","checksum":{"value":"BwgJ","algorithmOID":"2.16.840.1.101.3.4.2.1"},"signature_format":"P","responseURI":"https://example.test/signatures/1"}""",
        )
    }

    test("qes signature request flattens inline document data") {
        QesSignatureRequest(
            document = DocumentData(label = "Inline", document = byteArrayOf(1, 2, 3)),
        ).shouldRoundTripAs("""{"label":"Inline","document":"AQID"}""")
    }

    test("qes approval document flattens both documentInfo and documentReference forms") {
        val infoForm = QesApprovalDocument(documentInfo = DocumentInfo(label = "Contract", hash = byteArrayOf(1, 2, 3)))
        val encodedInfo = bindingJson.encodeToString(infoForm)
        Json.parseToJsonElement(encodedInfo) shouldBe Json.parseToJsonElement("""{"label":"Contract","hash":"AQID"}""")
        bindingJson.decodeFromString<QesApprovalDocument>(encodedInfo).documentInfo?.hash?.contentEquals(byteArrayOf(1, 2, 3)) shouldBe true

        val referenceForm = QesApprovalDocument(documentReference = DocumentReference(label = "Terms", href = "https://example.test/terms.pdf"))
        val encodedReference = bindingJson.encodeToString(referenceForm)
        Json.parseToJsonElement(encodedReference) shouldBe
                Json.parseToJsonElement("""{"label":"Terms","href":"https://example.test/terms.pdf"}""")
        bindingJson.decodeFromString<QesApprovalDocument>(encodedReference).documentReference?.href shouldBe
                "https://example.test/terms.pdf"
    }

    test("qes response uses CSC Base64 encoding inside the X.509 response") {
        X509PresentationResponse(
            qes = QesResponse(documentWithSignature = listOf(byteArrayOf(1, 2, 3))),
        ).shouldRoundTripAs("""{"qes":{"documentWithSignature":["AQID"]}}""")
    }

    test("X.509 metadata query serializes fingerprints, policies, and key constraints") {
        X509MetadataQuery(
            certificateFingerprints = listOf(Hash(byteArrayOf(4, 5), ObjectIdentifier("2.16.840.1.101.3.4.2.1"))),
            certificatePolicies = listOf("1.2.3.4"),
            keys = listOf(X509KeyInfo(algo = "1.2.840.10045.4.3.2", curve = "1.2.840.10045.3.1.7")),
        ).shouldRoundTripAs(
            """{"certificateFingerprints":[{"value":"BAU=","algorithmOID":"2.16.840.1.101.3.4.2.1"}],"certificatePolicies":["1.2.3.4"],"keys":[{"algo":"1.2.840.10045.4.3.2","curve":"1.2.840.10045.3.1.7"}]}""",
        )
    }

    test("qesApproval identifiers match the credential-format binding") {
        QesApprovalBinding.NAMESPACE shouldBe "org.cloudsignatureconsortium.dm.1"
        QesApprovalBinding.DATA_ELEMENT_IDENTIFIER shouldBe "qesApproval"
        QesApprovalBinding.SD_JWT_CLAIM shouldBe "org.cloudsignatureconsortium.dm.1.qesApproval"
    }
}
