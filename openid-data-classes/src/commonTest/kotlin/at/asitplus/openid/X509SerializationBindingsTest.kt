package at.asitplus.openid

import at.asitplus.csc.bindings.QesResponse
import at.asitplus.csc.bindings.X509KeyInfo
import at.asitplus.csc.bindings.X509MetadataQuery
import at.asitplus.csc.bindings.X509PresentationResponse
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.Digest
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlin.io.encoding.Base64

val X509SerializationBindingsTest by matrixSuite {
    test("X.509 metadata query and response binding shapes") {
        // Synthetic fixtures exercise the binding shapes; they are not copied specification vectors.
        val query = X509MetadataQuery(
            certificateFingerprints = listOf(
                Hash(
                    value = Base64.decode("HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="),
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
