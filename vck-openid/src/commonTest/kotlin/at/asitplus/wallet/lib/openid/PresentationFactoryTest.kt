package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToHexString

val  PresentationFactoryTest by testSuite {

    lateinit var presentationFactory: PresentationFactory

    testConfig = TestConfig.aroundEach {
        val keyMaterial = EphemeralKeyWithoutCert()
        presentationFactory = PresentationFactory(
            supportedAlgorithms = setOf(SignatureAlgorithm.ECDSAwithSHA256),
            signDeviceAuthDetached = SignCoseDetached(keyMaterial, CoseHeaderNone(), CoseHeaderNone()),
            signIdToken = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
            randomSource = RandomSource.Default
        )
        it()
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2.6.1-7
    "Sample from OpenID4VP 1.0" {
        val jsonWebKey  = """
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

        presentationFactory.calcSessionTranscript(
            clientId = "x509_san_dns:example.com",
            responseUrl = "https://example.com/response",
            nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            jsonWebKeys = listOf(jsonWebKey),
            responseWillBeEncrypted = true,
        ).apply {
            coseCompliantSerializer.encodeToHexString(this) shouldBe """
                83f6f682714f70656e494434565048616e646f7665725820048bc053c00442af9b8e
                ed494cefdd9d95240d254b046b11b68013722aad38ac
            """.trimIndent().replace("\n", "")
        }
    }

    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html#appendix-B.2.6.2-7
    "Sample from OpenID4VP 1.0 for DCAPI" {
        val jsonWebKey  = """
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

        presentationFactory.calcSessionTranscriptForDcApi(
            callingOrigin = "https://example.com",
            nonce = "exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA",
            jsonWebKeys = listOf(jsonWebKey),
            responseWillBeEncrypted = true,
        ).apply {
            coseCompliantSerializer.encodeToHexString(this) shouldBe """
                83f6f682764f70656e4944345650444341504948616e646f7665725820fbece366f4
                212f9762c74cfdbf83b8c69e371d5d68cea09cb4c48ca6daab761a
            """.trimIndent().replace("\n", "")
        }
    }
}