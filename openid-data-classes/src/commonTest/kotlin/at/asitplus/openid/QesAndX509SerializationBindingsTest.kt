package at.asitplus.openid

import at.asitplus.csc.bindings.QesResponse
import at.asitplus.csc.bindings.X509KeyInfo
import at.asitplus.csc.bindings.X509MetadataQuery
import at.asitplus.csc.bindings.X509PresentationResponse
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
val QesAndX509SerializationBindingsTest by matrixSuite {
    test("ETSI Annex A.12 QES request and response serialization examples") {
        val annexARequest = """{
            "type":"https://cloudsignatureconsortium.org/2025/qes",
            "credential_ids":["qes-cert-1"],
            "signatureRequests":[
                {
                    "label":"Service Agreement #2025-09",
                    "checksum":{"value":"sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=","algorithmOID":"2.16.840.1.101.3.4.2.1"},
                    "access":{"type":"OTP","oneTimePassword":"51623"},
                    "href":"https://protected.rp.example/contracts/2025-09-01.pdf?token=...",
                    "signature_format":"P",
                    "conformance_level":"AdES-B-B",
                    "signed_envelope_property":"Certification",
                    "signatureQualifier":"eu_eidas_qes",
                    "signAlgo":"1.2.840.113549.1.1.1"
                },
                {
                    "label":"Annex A - JSON config",
                    "href":"data:application/json;base64,eyJleGFtcGxlS2V5IjoiZXhhbXBsZVZhbHVlIn0K",
                    "signature_format":"J",
                    "conformance_level":"AdES-B-B",
                    "signed_envelope_property":"Attached",
                    "signAlgo":"1.2.840.113549.1.1.1",
                    "checksum":{"value":"cuKv8Ee9H/rQsteQ1MQZ2Ld2ERXRkkulihFh3/XOXFQ=","algorithmOID":"2.16.840.1.101.3.4.2.1"},
                    "signatureQualifier":"eu_eidas_qes"
                }
            ]
        }""".trimIndent()
        val request = Json.decodeFromString<TransactionData>(annexARequest)
            .shouldBeInstanceOf<QesRequest>()
        request.signatureQualifier shouldBe null
        request.signatureRequests.map { it.signatureQualifier } shouldBe listOf(
            SignatureQualifier.EU_EIDAS_QES,
            SignatureQualifier.EU_EIDAS_QES,
        )
        request.signatureRequests.first().checksum?.digest shouldBe Digest.SHA256
        Json.parseToJsonElement(Json.encodeToString<TransactionData>(request)) shouldBe
                Json.parseToJsonElement(annexARequest)

        val response = QesResponse(documentWithSignature = listOf(byteArrayOf(1, 2, 3)))
        val responseJson = Json.encodeToString(response)
        responseJson shouldBe """{"documentWithSignature":["AQID"]}"""
        Json.decodeFromString<QesResponse>(responseJson).documentWithSignature?.single()
            ?.contentEquals(byteArrayOf(1, 2, 3)) shouldBe true
        val detached = QesResponse(signatureObject = listOf(byteArrayOf(4, 5, 6)))
        Json.decodeFromString<QesResponse>(Json.encodeToString(detached)).signatureObject?.single()
            ?.contentEquals(byteArrayOf(4, 5, 6)) shouldBe true
    }

    test("CSC Data Model Bindings 8.1 and 8.2 X.509 examples") {
        val query = X509MetadataQuery(
            certificateFingerprints = listOf(
                Hash(
                    value = Base64.Default.decode("HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="),
                    algorithmOid = Digest.SHA256.oid,
                ),
            ),
            certificatePolicies = listOf("0.4.0.194112.1.2"),
            keys = listOf(X509KeyInfo(algo = "1.2.840.10045.4.3.2", curve = "1.2.840.10045.3.1.7")),
        )
        val queryJson = Json.encodeToString(query)
        queryJson shouldBe """{"certificateFingerprints":[{"value":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","algorithmOID":"2.16.840.1.101.3.4.2.1"}],"certificatePolicies":["0.4.0.194112.1.2"],"keys":[{"algo":"1.2.840.10045.4.3.2","curve":"1.2.840.10045.3.1.7"}]}"""
        Json.decodeFromString<X509MetadataQuery>(queryJson) shouldBe query

        val response = X509PresentationResponse(qes = QesResponse(documentWithSignature = listOf(byteArrayOf(1, 2, 3))))
        val responseJson = Json.encodeToString(response)
        responseJson shouldBe """{"qes":{"documentWithSignature":["AQID"]}}"""
        Json.decodeFromString<X509PresentationResponse>(responseJson) shouldBe response
    }
}
