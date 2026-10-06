package at.asitplus.wallet.lib.validation

import at.asitplus.signum.indispensable.cosef.CoseAlgorithm
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.cbor.CoseHeaderIdentifierFun
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.validation.CheckOutcome.Failed
import at.asitplus.wallet.lib.validation.CheckOutcome.Passed
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

private val payload = JsonObject(mapOf("iss" to JsonPrimitive("https://issuer.example.com")))

/** Signs with [signer], letting [header] set the header the way the test needs it. */
private suspend fun jws(
    signer: KeyMaterial,
    header: suspend (JwsHeader) -> JwsHeader,
): JwsCompact = SignJwt<JsonObject>(signer, JwsHeaderIdentifierFun { it, _ -> header(it) })
    .invoke(null, payload, JsonObject.serializer()).getOrThrow().jws

private suspend fun KeyMaterial.chain() = listOf(getCertificate().shouldNotBeNull())

private suspend fun cose(
    signer: KeyMaterial,
    protectedHeader: suspend (CoseHeader) -> CoseHeader = { it },
    unprotectedHeader: suspend (CoseHeader) -> CoseHeader = { it },
): CoseSigned<ByteArray> = SignCose<ByteArray>(
    keyMaterial = signer,
    protectedHeaderModifier = CoseHeaderIdentifierFun { it, _ -> protectedHeader(it ?: CoseHeader()) },
    unprotectedHeaderModifier = CoseHeaderIdentifierFun { it, _ -> unprotectedHeader(it ?: CoseHeader()) },
).invoke(null, null, byteArrayOf(1, 2, 3), ByteArraySerializer()).getOrThrow()

private suspend fun KeyMaterial.derChain() = listOf(getCertificate().shouldNotBeNull().encodeToDer())

private fun CheckOutcome.failureMessage() = shouldBeInstanceOf<Failed>().throwable.message.shouldNotBeNull()

val SignatureCheckTest by matrixSuite {
    val check = SignatureCheck()

    "JWS" - {
        "x5c only verifies with the leaf, and returns the chain for the trust check" {
            val signer = EphemeralKeyWithSelfSignedCert()
            val verification = check.verify(jws(signer) { it.copy(certificateChain = signer.chain()) })

            verification.outcome shouldBe Passed
            verification.certificateChain shouldBe signer.chain()
            verification.key shouldBe signer.publicKey
        }

        "jwk only verifies with it" {
            val signer = EphemeralKeyWithoutCert()
            val verification = check.verify(jws(signer) { it.copy(jsonWebKey = signer.jsonWebKey) })

            verification.outcome shouldBe Passed
            verification.certificateChain.shouldBeNull()
        }

        "jwk with the key of the x5c leaf verifies" {
            val signer = EphemeralKeyWithSelfSignedCert()

            check.verify(jws(signer) { it.copy(jsonWebKey = signer.jsonWebKey, certificateChain = signer.chain()) })
                .outcome shouldBe Passed
        }

        // The forgery VerifyJwsObject accepts: signed with the attacker's jwk, next to a chain the trust check accepts
        "jwk of another key than the x5c leaf fails, although the signature verifies with the jwk" {
            val trusted = EphemeralKeyWithSelfSignedCert()
            val attacker = EphemeralKeyWithoutCert()
            val verification = check.verify(
                jws(attacker) { it.copy(jsonWebKey = attacker.jsonWebKey, certificateChain = trusted.chain()) }
            )

            verification.outcome.failureMessage() shouldContain "different keys"
            verification.key.shouldBeNull()
            verification.certificateChain shouldBe trusted.chain()
        }

        "a did:key in kid verifies, but must not differ from the x5c leaf" {
            val signer = EphemeralKeyWithSelfSignedCert()
            val other = EphemeralKeyWithoutCert()

            check.verify(jws(signer) { it.copy(keyId = signer.publicKey.didEncoded) }).outcome shouldBe Passed
            check.verify(
                jws(signer) { it.copy(keyId = other.publicKey.didEncoded, certificateChain = signer.chain()) }
            ).outcome.failureMessage() shouldContain "different keys"
        }

        "a kid that only names a key is no key" {
            val signer = EphemeralKeyWithSelfSignedCert()

            check.verify(jws(signer) { it.copy(keyId = "key-1", certificateChain = signer.chain()) })
                .outcome shouldBe Passed
        }

        "a tampered payload fails" {
            val signer = EphemeralKeyWithoutCert()
            val (header, _, signature) = jws(signer) { it.copy(jsonWebKey = signer.jsonWebKey) }.toString().split(".")
            val forgedPayload = JsonObject(mapOf("iss" to JsonPrimitive("https://attacker.example.com"))).toString()
                .encodeToByteArray().encodeToString(Base64UrlStrict)
            val tampered = JwsCompact("$header.$forgedPayload.$signature")

            check.verify(tampered).outcome.shouldBeInstanceOf<Failed>()
        }

        "a key given by the caller is the only one used" {
            val holder = EphemeralKeyWithoutCert()
            val other = EphemeralKeyWithoutCert()
            val signed = jws(holder) { it.copy(jsonWebKey = other.jsonWebKey) }

            check.verify(signed, key = holder.publicKey).outcome shouldBe Passed
            check.verify(signed, key = other.publicKey).outcome.shouldBeInstanceOf<Failed>()
        }

        "without any key it fails" {
            check.verify(jws(EphemeralKeyWithoutCert()) { it.copy(jsonWebKey = null, keyId = null) })
                .outcome.failureMessage() shouldContain "No key"
        }

        "a jku is never followed" {
            val signer = EphemeralKeyWithoutCert()
            val signed = jws(signer) {
                it.copy(jsonWebKey = null, keyId = "signer", jsonWebKeySetUrl = "https://issuer.example.com/jwks")
            }

            check.verify(signed).outcome.failureMessage() shouldContain "No key"
            check.verify(signed, key = signer.publicKey).outcome shouldBe Passed
        }
    }

    "COSE" - {
        "x5chain in the unprotected or the protected header verifies with the leaf" {
            val signer = EphemeralKeyWithSelfSignedCert()

            check.verify(cose(signer, unprotectedHeader = { it.copy(certificateChain = signer.derChain()) }))
                .let {
                    it.outcome shouldBe Passed
                    it.certificateChain shouldBe signer.chain()
                    it.key shouldBe signer.publicKey
                }
            check.verify(cose(signer, protectedHeader = { it.copy(certificateChain = signer.derChain()) }))
                .outcome shouldBe Passed
        }

        "different chains in the protected and unprotected header fail" {
            val signer = EphemeralKeyWithSelfSignedCert()
            val other = EphemeralKeyWithSelfSignedCert()
            val signed = cose(
                signer,
                protectedHeader = { it.copy(certificateChain = signer.derChain()) },
                unprotectedHeader = { it.copy(certificateChain = other.derChain()) },
            )

            check.verify(signed).outcome.failureMessage() shouldContain "different certificate chains"
        }

        "a did:key in kid other than the x5chain leaf fails" {
            val signer = EphemeralKeyWithSelfSignedCert()
            val attacker = EphemeralKeyWithoutCert()
            val signed = cose(
                attacker,
                protectedHeader = { it.copy(kid = attacker.publicKey.didEncoded.encodeToByteArray()) },
                unprotectedHeader = { it.copy(certificateChain = signer.derChain()) },
            )

            check.verify(signed).outcome.failureMessage() shouldContain "different keys"
        }

        "other external data fails" {
            val signer = EphemeralKeyWithSelfSignedCert()
            val signed = cose(signer, unprotectedHeader = { it.copy(certificateChain = signer.derChain()) })

            check.verify(signed, externalAad = byteArrayOf(9)).outcome.shouldBeInstanceOf<Failed>()
        }

        "a MAC algorithm fails" {
            val signer = EphemeralKeyWithSelfSignedCert()
            val signed = cose(
                signer,
                protectedHeader = { it.copy(algorithm = CoseAlgorithm.MAC.HS256) },
                unprotectedHeader = { it.copy(certificateChain = signer.derChain()) },
            )

            check.verify(signed).outcome.failureMessage() shouldContain "not an asymmetric signature algorithm"
        }
    }
}
