package at.asitplus.openid

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRAR_DATASET_FORMAT
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/** Registrar-provided data as in ETSI TS 119 472-2 V1.3.1 OIDFVP-HAIP-COMMON-REQ-RO-06 to RO-11. */
private val registrarDataset: JsonObject = buildJsonObject {
    putJsonArray("identifier") {
        add(buildJsonObject {
            put("type", "http://data.europa.eu/eudi/id/EUID")
            put("identifier", "DEXXX.HRB1")
        })
    }
    putJsonArray("srvDescription") {
        add(buildJsonObject {
            put("lang", "en")
            put("content", "Service")
        })
    }
    put("registryURI", "https://registrar.example.com")
    put("intendedUseIdentifier", "intended-use-1")
    putJsonArray("purpose") {
        add(buildJsonObject {
            put("lang", "en")
            put("content", "Purpose")
        })
    }
    put("policyURI", "https://example.com/privacy-policy")
}

val VerifierInfoSerializationTest by matrixSuite {

    test("string data round-trips as a JSON string") {
        val verifierInfo = VerifierInfo(REGISTRATION_CERT_FORMAT, "eyJhbGciOiJFUzI1NiJ9.e30.c2ln", setOf("pid"))

        val json = joseCompliantSerializer.encodeToString(VerifierInfo.serializer(), verifierInfo)

        json shouldBe """{"format":"registration_cert","data":"eyJhbGciOiJFUzI1NiJ9.e30.c2ln","credential_ids":["pid"]}"""
        joseCompliantSerializer.decodeFromString(VerifierInfo.serializer(), json).apply {
            this shouldBe verifierInfo
            data.shouldBeInstanceOf<VerifierInfo.Data.StringData>().value shouldBe "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
        }
    }

    test("object data round-trips as a JSON object") {
        val verifierInfo = VerifierInfo(REGISTRAR_DATASET_FORMAT, registrarDataset)

        val json = joseCompliantSerializer.encodeToString(VerifierInfo.serializer(), verifierInfo)

        joseCompliantSerializer.parseToJsonElement(json).jsonObject["data"] shouldBe registrarDataset
        joseCompliantSerializer.decodeFromString(VerifierInfo.serializer(), json).apply {
            this shouldBe verifierInfo
            data.shouldBeInstanceOf<VerifierInfo.Data.ObjectData>().value shouldBe registrarDataset
        }
    }

    test("data other than a string or an object is rejected") {
        listOf("42", "true", "null", buildJsonArray { }.toString()).forEach { data ->
            shouldThrow<SerializationException> {
                joseCompliantSerializer.decodeFromString(
                    VerifierInfo.serializer(),
                    """{"format":"other","data":$data}""",
                )
            }
        }
    }

    test("authentication request with string and object verifier_info round-trips in JSON and form encoding") {
        val parameters = AuthenticationRequestParameters(
            clientId = "x509_hash:abc",
            nonce = "nonce",
            verifierInfo = nonEmptyListOf(
                VerifierInfo(REGISTRATION_CERT_FORMAT, "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"),
                VerifierInfo(REGISTRAR_DATASET_FORMAT, registrarDataset),
            ),
        )

        val json = joseCompliantSerializer.encodeToString(AuthenticationRequestParameters.serializer(), parameters)
        joseCompliantSerializer.decodeFromString(AuthenticationRequestParameters.serializer(), json) shouldBe parameters

        parameters.encodeToParameters().decode<AuthenticationRequestParameters>().verifierInfo
            .shouldNotBeNull() shouldBe parameters.verifierInfo
    }

    test("registrar dataset of an incoming request is kept as an object") {
        val json = buildJsonObject {
            put("nonce", "nonce")
            putJsonArray("verifier_info") {
                add(buildJsonObject {
                    put("format", REGISTRAR_DATASET_FORMAT)
                    put("data", registrarDataset)
                })
            }
        }.toString()

        joseCompliantSerializer.decodeFromString(AuthenticationRequestParameters.serializer(), json)
            .verifierInfo.shouldNotBeNull().single().data
            .shouldBeInstanceOf<VerifierInfo.Data.ObjectData>().value shouldBe registrarDataset
    }
}
