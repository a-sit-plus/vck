package at.asitplus.openid

import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.buildJsonArray

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
}
