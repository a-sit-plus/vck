package at.asitplus.openid

import at.asitplus.csc.bindings.QesSignatureRequest
import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.ConformanceLevel
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureFormat
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.basic.SignedEnvelopeProperty
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.AccessControlMethod
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64

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
            "checksum":"sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "signature_format":"P",
            "conformance_level":"AdES-B-B",
            "signed_envelope_property":"Certification",
            "signAlgo":"1.2.840.113549.1.1.1"
        },
        {
            "label":"Example Terms of Service",
            "access":{"type":"public"},
            "href":"https://public.rp-cdn.example/terms-and-conditions.pdf",
            "checksum":"sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
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

val QesTransactionDataBindingsTest by matrixSuite {
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
                        checksum = Hash(
                            value = Base64.decode("sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="),
                            algorithmOid = Digest.SHA256.oid,
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
                        checksum = Hash(
                            value = Base64.decode("HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="),
                            algorithmOid = Digest.SHA256.oid,
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

}
