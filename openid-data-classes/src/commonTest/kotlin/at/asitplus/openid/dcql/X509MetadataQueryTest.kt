package at.asitplus.openid.dcql

import at.asitplus.csc.bindings.X509KeyInfo
import at.asitplus.csc.datamodel.basic.Hash
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json

val X509MetadataQueryTest by matrixSuite {
    "X.509 metadata query serializes fingerprints, policies, and key constraints" {
        val query = X509MetadataQuery(
            certificateFingerprints = listOf(Hash(byteArrayOf(4, 5), ObjectIdentifier("2.16.840.1.101.3.4.2.1"))),
            certificatePolicies = listOf("1.2.3.4"),
            keys = listOf(X509KeyInfo(algo = "1.2.840.10045.4.3.2", curve = "1.2.840.10045.3.1.7")),
        )
        val expected =
            """{"certificateFingerprints":[{"value":"BAU=","algorithmOID":"2.16.840.1.101.3.4.2.1"}],"certificatePolicies":["1.2.3.4"],"keys":[{"algo":"1.2.840.10045.4.3.2","curve":"1.2.840.10045.3.1.7"}]}"""
        val json = Json {
            encodeDefaults = false
            explicitNulls = false
        }

        val encoded = json.encodeToString(query)
        Json.parseToJsonElement(encoded) shouldBe Json.parseToJsonElement(expected)
        json.decodeFromString<X509MetadataQuery>(encoded) shouldBe query
    }
}
