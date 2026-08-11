package at.asitplus.wallet.lib.openid

import at.asitplus.dif.ClaimFormat
import at.asitplus.openid.SupportedAlgorithmsContainerIso
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToHexString

val PresentationFactoryTest by matrixSuite {

    fixture {
        object {
            val presentationFactory = PresentationFactory(
                supportedAlgorithms = setOf(SignatureAlgorithm.ECDSAwithSHA256)
            )
        }
    } - {

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-a-set-of-static-configurati
        "Sample vp_formats_supported entries" {
            val vpFormatsSupported = """
                {
                    "dc+sd-jwt": {
                      "sd-jwt_alg_values": [
                        "ES256"
                      ],
                      "kb-jwt_alg_values": [
                        "ES256"
                      ]
                    },
                    "mso_mdoc": {}
                  }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<VpFormatsSupported>(it)
            }

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe true

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe true
        }

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-a-set-of-static-configurati
        "Sample vp_formats_supported entries not matching" {
            val vpFormatsSupported = """
                {
                    "dc+sd-jwt": {
                      "sd-jwt_alg_values": [ "ES384" ],
                      "kb-jwt_alg_values": [ "ES384" ]
                    },
                    "mso_mdoc": {
                      "issuerauth_alg_values": [ -1 ],
                      "deviceauth_alg_values": [ -1 ]
                    }
                  }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<VpFormatsSupported>(it)
            }

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe false

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(),
                supportedCoseAlgorithms = listOf(),
            ) shouldBe false

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe false

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(),
                supportedCoseAlgorithms = listOf(),
            ) shouldBe false
        }

        "fully-specified COSE algorithm matches its legacy equivalent" {
            VpFormatsSupported(
                msoMdoc = SupportedAlgorithmsContainerIso(
                    issuerAuthAlgorithmInts = setOf(CoseAlgorithm.Signature.ESP256.coseValue),
                    deviceAuthAlgorithmInts = setOf(CoseAlgorithm.Signature.ESP256.coseValue),
                )
            ).supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = emptyList(),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe true
        }

        "empty vp_formats_supported not matching" {
            val vpFormatsSupported = """
                { }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<VpFormatsSupported>(it)
            }

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe false

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(),
                supportedCoseAlgorithms = listOf(),
            ) shouldBe false

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe false

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(),
                supportedCoseAlgorithms = listOf(),
            ) shouldBe false
        }

        "Empty vp_formats_supported entries" {
            val vpFormatsSupported = """
                {
                    "dc+sd-jwt": {},
                    "mso_mdoc": {}
                  }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<VpFormatsSupported>(it)
            }

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe true

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(JwsAlgorithm.Signature.ES256),
                supportedCoseAlgorithms = listOf(CoseAlgorithm.Signature.ES256),
            ) shouldBe true

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.MSO_MDOC,
                supportedJwsAlgorithms = listOf(),
                supportedCoseAlgorithms = listOf(),
            ) shouldBe true

            vpFormatsSupported.supportsAlgorithm(
                claimFormat = ClaimFormat.SD_JWT,
                supportedJwsAlgorithms = listOf(),
                supportedCoseAlgorithms = listOf(),
            ) shouldBe true
        }

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2.6.1-7
        test("Sample from OpenID4VP 1.0") {
            val jsonWebKey = """
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                  "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                  "use": "enc",
                  "alg": "ECDH-ES",
                  "kid": "1"
                }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<JsonWebKey>(it)
            }

            it.presentationFactory.calcSessionTranscript(
                clientId = "x509_san_dns:example.com",
                responseUrl = "https://example.com/response",
                nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                recipientKey = jsonWebKey,
            ).apply {
                coseCompliantSerializer.encodeToHexString(this) shouldBe """
                    83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
                    ed494cefdd9d95240d254b046b11b68013722aad38ac
                """.trimIndent().replace("\n", "")
            }
        }

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2.6.2-7
        "Sample from OpenID4VP 1.0 for DCAPI" { it ->
            val jsonWebKey = """
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                  "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                  "use": "enc",
                  "alg": "ECDH-ES",
                  "kid": "1"
                }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<JsonWebKey>(it)
            }

            it.presentationFactory.calcSessionTranscript(
                nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                dcApiRequestCallingOrigin = "https://example.com",
                recipientKey = jsonWebKey
            ).apply {
                coseCompliantSerializer.encodeToHexString(this) shouldBe """
                    83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4
                    212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a
                """.trimIndent().replace("\n", "")
            }
        }

        "ISO mdoc rejects an opaque DC API origin" {
            shouldThrow<IllegalArgumentException> {
                it.presentationFactory.calcSessionTranscript(
                    nonce = "nonce",
                    dcApiRequestCallingOrigin = "android:apk-key-hash:AbCdEf",
                )
            }
        }

        "OpenID4VP DCAPI SessionTranscript serializes origin before hashing" { it ->
            val jsonWebKey = """
                {
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "DxiH5Q4Yx3UrukE2lWCErq8N8bqC9CHLLrAwLz5BmE0",
                  "y": "XtLM4-3h5o3HUH0MHVJV0kyq0iBlrBwlh8qEDMZ4-Pc",
                  "use": "enc",
                  "alg": "ECDH-ES",
                  "kid": "1"
                }
            """.trimIndent().let {
                joseCompliantSerializer.decodeFromString<JsonWebKey>(it)
            }

            it.presentationFactory.calcSessionTranscript(
                nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
                dcApiRequestCallingOrigin = "https://example.com/",
                recipientKey = jsonWebKey
            ).apply {
                coseCompliantSerializer.encodeToHexString(this) shouldBe """
                    83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4
                    212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a
                """.trimIndent().replace("\n", "")
            }
        }
    }
}
