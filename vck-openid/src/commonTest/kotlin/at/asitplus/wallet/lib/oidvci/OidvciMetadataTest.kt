package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.DisplayProperties
import at.asitplus.openid.IssuerInfo
import at.asitplus.openid.OpenIdConstants
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.oauth2.SimpleAuthorizationService
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import io.kotest.matchers.collections.shouldHaveSingleElement
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put

val OidvciMetadataTest by matrixSuite {

    fixture {
        object {
            val authorizationService = SimpleAuthorizationService(
                strategy = CredentialAuthorizationServiceStrategy(AttributeIndex.schemeSet),
            )
            val issuer = OpenId4VciServer(
                authorizationService = authorizationService,
                issuer = IssuerAgent(
                    identifier = "https://issuer.example.com".toUri(),
                    randomSource = RandomSource.Default
                ),
                credentialSchemes = AttributeIndex.schemeSet,
                displayProperties = setOf(DisplayProperties(name = "Example Issuer", locale = "en")),
            )
        }
    } - {
        test("signed metadata as per OID4VCI 1.0, Section 12.2.3") {
            val signed = it.issuer.signedMetadata().getOrThrow()

            signed.jws.jwsHeader.type shouldBe OpenIdConstants.ISSUER_METADATA_JWT_TYPE
            VerifyJwsObject()(signed.jws).getOrThrow()
            joseCompliantSerializer.decodeFromString<JsonObject>(signed.jws.plainPayload.decodeToString()).apply {
                get("sub").shouldNotBeNull().jsonPrimitive.content shouldBe it.issuer.metadata.credentialIssuer
                get("iat").shouldNotBeNull().jsonPrimitive.long
                get("credential_issuer").shouldNotBeNull()
                get("display").shouldNotBeNull()
            }
            // claims of the signed metadata only
            it.issuer.metadata.subject.shouldBeNull()
            it.issuer.metadata.issuedAt.shouldBeNull()
        }

        test("signed metadata carry issuer_info at the top level, as ETSI TS 119 472-3 V1.1.1, 4.2.3") {
            val issuerInfo = listOf(
                IssuerInfo(
                    format = OpenIdConstants.IssuerInfo.REGISTRAR_DATASET_FORMAT,
                    data = buildJsonObject { put("registryURI", "https://registrar.example.com") },
                ),
                IssuerInfo(format = OpenIdConstants.IssuerInfo.REGISTRATION_CERT_FORMAT, data = JsonPrimitive("a.b.c")),
            )
            val issuer = OpenId4VciServer(
                authorizationService = it.authorizationService,
                issuer = IssuerAgent(identifier = "https://issuer.example.com".toUri()),
                credentialSchemes = AttributeIndex.schemeSet,
                issuerInfo = issuerInfo,
            )

            val signed = issuer.signedMetadata().getOrThrow()

            signed.payload.issuerInfo shouldBe issuerInfo
            joseCompliantSerializer.decodeFromString<JsonObject>(signed.jws.plainPayload.decodeToString())
                .get("issuer_info").shouldNotBeNull().jsonArray.size shouldBe 2
            // only in the signed metadata
            issuer.metadata.issuerInfo.shouldBeNull()
        }

        test("metadata for ISO_MDOC") {
            joseCompliantSerializer.encodeToJsonElement(it.issuer.metadata).jsonObject.apply {
                get("credential_configurations_supported").shouldNotBeNull().jsonObject.apply {
                    get(MDL_DOCTYPE).shouldNotBeNull().jsonObject.apply {
                        get("credential_signing_alg_values_supported").shouldNotBeNull().jsonArray.apply {
                            shouldHaveSingleElement(JsonPrimitive(-9))
                        }
                    }
                }
            }
        }
    }
}
