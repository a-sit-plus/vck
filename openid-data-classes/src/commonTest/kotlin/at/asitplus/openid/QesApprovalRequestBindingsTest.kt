package at.asitplus.openid

import at.asitplus.csc.bindings.QesApprovalDocument
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.documents.AccessControlMethod
import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val QesApprovalRequestBindingsTest by matrixSuite {
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

    test("non-normative CSC Data Model Bindings 7.1.2 example adapted to ETSI TS 119 432") {
        // The published example is non-normative; use the structured checksum required by the TS profile.
        val publishedVector = """{
            "type":"https://cloudsignatureconsortium.org/2025/qes-approval",
            "credential_ids":["xyz123"],
            "numSignatures":2,
            "signatureQualifier":"eu_eidas_qes",
            "documentInfos":[
                {"label":"Example Contract","hash":"sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=","hashType":"sodr","access":{"type":"OTP","oneTimePassword":"51623"},"href":"https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374","checksum":{"value":"sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=","algorithmOID":"2.16.840.1.101.3.4.2.1"}},
                {"label":"Example Terms of Service","hash":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","hashType":"sodr","access":{"type":"public"},"href":"https://public.rp-cdn.example/terms-and-conditions.pdf","checksum":{"value":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","algorithmOID":"2.16.840.1.101.3.4.2.1"}},
                {"label":"Example Invoice","hash":"nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=","hashType":"sodr","access":{"type":"OTP","oneTimePassword":"83920"},"href":"https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a","checksum":{"value":"nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=","algorithmOID":"2.16.840.1.101.3.4.2.1"}}
            ],
            "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
        }""".trimIndent()

        val decoded = Json.decodeFromString<TransactionData>(publishedVector)
            .shouldBeInstanceOf<QesApprovalRequest>()
        decoded.credentialIds shouldBe setOf("xyz123")
        decoded.numSignatures shouldBe 2
        decoded.documentDigests.size shouldBe 3
        decoded.documentDigests.first().documentInfo?.label shouldBe "Example Contract"
        decoded.documentDigests.first().documentInfo?.hashType shouldBe at.asitplus.csc.datamodel.documents.HashType.SODR
        decoded.documentDigests.first().documentReference?.access shouldBe AccessControlMethod.OTP("51623")
        decoded.hashAlgorithmOid shouldBe ObjectIdentifier("2.16.840.1.101.3.4.2.1")
    }

    test("non-normative ETSI TS 119 432 Annex B.6.2 qesApprovalRequest example") {
        // This published example illustrates Annex B; normative requirements are tested separately.
        val publishedVector = """{
            "type":"https://cloudsignatureconsortium.org/2025/qes-approval",
            "credential_ids":["xyz123"],
            "credentialID":"GX0112348",
            "signatureQualifier":"eu_eidas_qes",
            "numSignatures":2,
            "documentDigests":[
                {"label":"Example Contract","hash":"sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=","hashType":"sodr","access":{"type":"OTP","oneTimePassword":"51623"},"href":"https://protected.example/doc-01.pdf?token=...","checksum":{"value":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","algorithmOID":"2.16.840.1.101.3.4.2.1"}},
                {"label":"Terms of Service","hash":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","hashType":"sodr","access":{"type":"public"},"href":"https://public.example/tos.pdf","checksum":{"value":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","algorithmOID":"2.16.840.1.101.3.4.2.1"}}
            ],
            "hashAlgorithmOID":"2.16.840.1.101.3.4.2.1"
        }""".trimIndent()

        val decoded = Json.decodeFromString<TransactionData>(publishedVector)
            .shouldBeInstanceOf<QesApprovalRequest>()
        decoded.credentialId shouldBe "GX0112348"
        decoded.documentDigests.size shouldBe 2
        decoded.documentDigests.first().documentReference?.checksum?.digest shouldBe Digest.SHA256
        decoded.documentDigests.first().documentReference?.href shouldBe "https://protected.example/doc-01.pdf?token=..."
        val reserialized = Json.parseToJsonElement(Json.encodeToString<TransactionData>(decoded))
        reserialized.jsonObject["documentDigests"]?.jsonArray?.size shouldBe 2
        reserialized.jsonObject["documentDigests"]?.jsonArray?.first()
            ?.jsonObject?.get("href")?.jsonPrimitive?.content shouldBe
                "https://protected.example/doc-01.pdf?token=..."
    }

}
