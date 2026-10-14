package at.asitplus.openid.dcql

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.QesRequest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.matrix.matrixSuite
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.disable
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

val DCQLX509CredentialQueryTest by matrixSuite {
    // Fingerprints follow the existing CSC Hash model; the other cases exercise A.6.3 policy/key constraints.
    listOf(
        "{}",
        """{"certificatePolicies":["0.4.0.2042.1","0.4.0.194112.1"]}""",
        """{"certificateFingerprints":[{"value":"Jal8JexCNec2FBjKNGNM6WSiiE44NWjbvJBHav+vCXU=","algorithmOID":"2.16.840.1.101.3.4.2.1"}]}""",
        """{"keys":[{"algo":"1.2.840.113549.1.1.1","len":2048},{"algo":"1.2.840.10045.2.1","curve":"1.2.840.10045.3.1.7"}]}""",
        """{"certificatePolicies":["0.4.0.2042.1"],"keys":[{"algo":"1.2.840.113549.1.1.1","len":2048}]}""",
    ).asData(nameFn = { "X.509 query preserves CSC metadata: $it" }) test { metadataJson ->
        val input = Json.parseToJsonElement(
            """{"id":"xyz123","format":"https://cloudsignatureconsortium.org/2025/x509","meta":$metadataJson}""",
        )
        val decoded = Json.decodeFromJsonElement<DCQLCredentialQuery>(input)
            .shouldBeInstanceOf<DCQLX509CredentialQuery>()

        decoded.id.string shouldBe "xyz123"
        decoded.format shouldBe CredentialFormatEnum.X509
        decoded.multiple shouldBe false
        decoded.requireCryptographicHolderBinding shouldBe true
        decoded.meta shouldBe Json.decodeFromString<X509MetadataQuery>(metadataJson)
        Json.encodeToJsonElement<DCQLCredentialQuery>(decoded) shouldBe input

        val baseMeta: DCQLCredentialMetadataAndValidityConstraints = decoded.meta
        val encodedMeta = Json.encodeToJsonElement(baseMeta)
        encodedMeta shouldBe Json.parseToJsonElement(metadataJson)
        if (metadataJson != "{}") {
            Json.decodeFromJsonElement<DCQLCredentialMetadataAndValidityConstraints>(encodedMeta) shouldBe baseMeta
        }
    }

    test("query factory preserves generic DCQL options") {
        val input = Json.parseToJsonElement(
            """{
                "id":"certificate", "format":"https://cloudsignatureconsortium.org/2025/x509",
                "meta":{}, "multiple":true, "require_cryptographic_holder_binding":false,
                "trusted_authorities":[{"type":"etsi_tl","values":["https://example.test/trust-list"]}],
                "claims":[{"id":"subject","path":["subject"]}], "claim_sets":[["subject"]]
            }""",
        )
        val decoded = Json.decodeFromJsonElement<DCQLCredentialQuery>(input)
            .shouldBeInstanceOf<DCQLX509CredentialQuery>()
        DCQLCredentialQuery(
            id = decoded.id,
            format = decoded.format,
            meta = decoded.meta,
            claims = decoded.claims,
            claimSets = decoded.claimSets,
            multiple = decoded.multiple,
            trustedAuthorities = decoded.trustedAuthorities,
            requireCryptographicHolderBinding = decoded.requireCryptographicHolderBinding,
        ) shouldBe decoded
        Json.encodeToJsonElement<DCQLCredentialQuery>(decoded) shouldBe input
    }

    test("A.6 authorization request parses X.509 DCQL and the original encoded QES transaction") {
        val transaction = """{
            "type":"https://cloudsignatureconsortium.org/2025/qes",
            "credential_ids":["xyz123"],
            "signatureRequests":[{
                "label":"Example Terms of Service", "access":{"type":"public"},
                "href":"https://public.rp-cdn.example/terms-and-conditions.pdf",
                "checksum":{"value":"HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=","algorithmOID":"2.16.840.1.101.3.4.2.1"},
                "signature_format":"P", "conformance_level":"AdES-B-B",
                "signed_envelope_property":"Certification", "signAlgo":"1.2.840.113549.1.1.1",
                "signatureQualifier":"eu_eidas_qes"
            }]
        }""".encodeToByteArray().encodeToString(Base64UrlStrict)
        val input = Json.parseToJsonElement(
            """{
                "response_type":"vp_token", "response_mode":"direct_post",
                "client_id":"https://rp.example/client", "response_uri":"https://rp.example/response",
                "state":"state", "nonce":"nonce",
                "dcql_query":{"credentials":[{
                    "id":"xyz123", "format":"https://cloudsignatureconsortium.org/2025/x509",
                    "meta":{"certificatePolicies":["0.4.0.2042.1","0.4.0.194112.1"]}
                }]},
                "transaction_data":["$transaction"]
            }""",
        )
        val request = Json.decodeFromJsonElement<AuthenticationRequestParameters>(input)
        val query = request.dcqlQuery.shouldNotBeNull().credentials.single()
            .shouldBeInstanceOf<DCQLX509CredentialQuery>()
        val qes = request.transactionDataDecoded.shouldNotBeNull().single().shouldBeInstanceOf<QesRequest>()

        qes.credentialIds shouldBe setOf(query.id.string)
        qes.signatureRequests.single().responseUri shouldBe null
        request.transactionData.shouldNotBeNull().single().content shouldBe transaction
        Json.encodeToJsonElement(request) shouldBe input
    }

    listOf(
        """{"id":"certificate","format":"https://cloudsignatureconsortium.org/2025/x509"}""",
        """{"id":"certificate","format":"https://cloudsignatureconsortium.org/2025/x509","meta":{"certificateFingerprints":[{"value":"AQID"}]}}""",
        """{"id":"certificate","format":"https://cloudsignatureconsortium.org/unknown/x509","meta":{}}""",
    ).asData(nameFn = { "Invalid X.509 query is rejected: $it" }) test { input ->
        shouldThrowAny { Json.decodeFromString<DCQLCredentialQuery>(input) }
    }

    test("concrete X.509 query rejects another credential format") {
        shouldThrowAny {
            DCQLX509CredentialQuery(
                id = DCQLCredentialQueryIdentifier("certificate"),
                meta = X509MetadataQuery(),
                format = CredentialFormatEnum.DC_SD_JWT,
            )
        }
    }

    // Enable once X.509 metadata matching is implemented. These assert the intended format checks, not TODO behavior.
    testSuite("X.509 metadata matching", testConfig = TestConfig.disable()) {
        val jsonClaims = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {})
        listOf<DCQLCredential>(
            DCQLSdJwtCredential(
                claimStructure = jsonClaims,
                type = "eu.pid.1",
                satisfiesCryptographicHolderBinding = true,
                authorityKeyIdentifiers = emptyList(),
            ),
            DCQLVcJwsCredential(
                claimStructure = jsonClaims,
                types = listOf("VerifiableCredential"),
                satisfiesCryptographicHolderBinding = true,
                authorityKeyIdentifiers = emptyList(),
            ),
            DCQLIsoMdocCredential(
                claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(emptyMap()),
                documentType = "eu.europa.ec.eudi.pid.1",
                satisfiesCryptographicHolderBinding = true,
                authorityKeyIdentifiers = emptyList(),
            ),
        ).asData(nameFn = { "X.509 metadata rejects a ${it.format.text} credential" }) test { credential ->
            X509MetadataQuery().validateCredentialConformance(credential)
                .exceptionOrNull().shouldBeInstanceOf<IllegalArgumentException>()
        }
    }
}
