package at.asitplus.wallet.lib.jws

import at.asitplus.catching
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.signum.supreme.sign.Verifier
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.random.Random

val JwsServiceTest by matrixSuite {


    fixture {
        object {
            val keyId = Random.nextBytes(16).encodeToString(Base64())
            val keyMaterial = EphemeralKeyWithoutCert(customKeyId = keyId)
            val signJwt = SignJwt<ByteArray>(keyMaterial, JwsHeaderCertOrJwk())
            val verifierJwsService = VerifyJwsObject()
            val randomPayload = uuid4().toString()

        }
    } - {
        test("signed object with bytes can be verified") {
            val payload = it.randomPayload.encodeToByteArray()
            val signed = it.signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()
            it.verifierJwsService(signed.jws).getOrThrow()
        }

        test("Object can be reconstructed") {
            val payload = it.randomPayload.encodeToByteArray()
            val signed =
                it.signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow().toString()

            val parsed = JwsCompactTyped<ByteArray>(signed)
            parsed.toString() shouldBe signed
            parsed.payload shouldBe payload
            it.verifierJwsService(parsed.jws).getOrThrow()
        }

        test("signed object can be verified") {
            val payload = it.randomPayload.encodeToByteArray()
            val signed = it.signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()
            it.verifierJwsService(signed.jws).getOrThrow()
        }

        test("signed object with jsonWebKey can be verified") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwk())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()
            it.verifierJwsService(signed.jws).getOrThrow()
        }

        test("signed object with kid from jku can be verified") {
            val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwksUrl(jku))
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()
            val validKey = it.keyMaterial.jsonWebKey
            val jwkSetRetriever = JwkSetRetrieverFunction { JsonWebKeySet(keys = listOf(validKey)) }
            VerifyJwsObject(jwkSetRetriever = jwkSetRetriever)(signed.jws).getOrThrow()
        }

        test("signed object with kid from jku, returning invalid key, can not be verified") {
            val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwksUrl(jku))
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()
            val invalidKey = EphemeralKeyWithoutCert().jsonWebKey
            val jwkSetRetriever = JwkSetRetrieverFunction { JsonWebKeySet(keys = listOf(invalidKey)) }
            shouldThrowAny { VerifyJwsObject(jwkSetRetriever = jwkSetRetriever)(signed.jws).getOrThrow() }
        }

        test("signed object without public key in header can not be verified") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderNone())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            shouldThrowAny { VerifyJwsObject()(signed.jws).getOrThrow() }
        }

        test("signed object without public key in header, but with a trusted key can be verified") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderNone())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            val trustedKeys = PublicJsonWebKeyLookup { _ -> setOf(it.keyMaterial.jsonWebKey) }
            VerifyJwsObjectTrusted(trustedKeys = trustedKeys)(signed.jws).getOrThrow()
        }

        test("signed object with jsonWebKey in header, that key being trusted, can be verified") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwk())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            val trustedKeys = PublicJsonWebKeyLookup { _ -> setOf(it.keyMaterial.jsonWebKey) }
            VerifyJwsObjectTrusted(trustedKeys = trustedKeys)(signed.jws).getOrThrow()
        }

        test("signed object with jsonWebKey in header, that key not being trusted, can not be verified") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwk())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            val trustedKeys = PublicJsonWebKeyLookup { _ -> setOf(EphemeralKeyWithoutCert().jsonWebKey) }
            shouldThrowAny { VerifyJwsObjectTrusted(trustedKeys = trustedKeys)(signed.jws).getOrThrow() }
        }

        test("signed object can not be verified against an empty trust list") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwk())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            val trustedKeys = PublicJsonWebKeyLookup { _ -> null }
            shouldThrowAny { VerifyJwsObjectTrusted(trustedKeys = trustedKeys)(signed.jws).getOrThrow() }
        }

        @Suppress("DEPRECATION")
        test("deprecated publicKeyLookup enforces its keys instead of the one in the header") {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwk())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            val publicKeyLookup = PublicJsonWebKeyLookup { _ -> setOf(EphemeralKeyWithoutCert().jsonWebKey) }
            shouldThrowAny { VerifyJwsObject(publicKeyLookup = publicKeyLookup)(signed.jws).getOrThrow() }
        }

        test("encrypted object can be decrypted") {
            val encrypter = EncryptJwe()
            val decrypterKey = EphemeralKeyWithoutCert()
            val decrypter = DecryptJwe(decrypterKey)

            val encrypted = encrypter(
                JweHeader(
                    algorithm = JweAlgorithm.ECDH_ES,
                    encryption = JweEncryption.A256GCM,
                    type = "anything",
                ),
                it.randomPayload,
                decrypterKey.jsonWebKey,
            ).getOrThrow().serialize().shouldNotBeNull()

            val parsed = JweEncrypted.deserialize(encrypted).getOrThrow()

            decrypter(parsed).getOrThrow()
                .shouldNotBeNull()
                .payload shouldBe it.randomPayload
        }

        val dummyVerifier = VerifyJwsObjectFun { catching { Verifier.Success } }
        val jadesVerifier = VerifyJwsObjectJades(verifyJwsObject = dummyVerifier)

        test("JAdES verification passes with valid x5t#o parameter (SHA-384)") {
            val keyWithCert = EphemeralKeyWithSelfSignedCert()
            val signed = SignJwt<ByteArray>(keyWithCert, JwsHeaderCertOrJwk())(
                JwsContentTypeConstants.JWT,
                it.randomPayload.encodeToByteArray(),
                ByteArraySerializer()
            ).getOrThrow()

            // Extract the actual JwsCompact to match the rest of the test suite
            val baseJws = signed.jws

            val validB64Url = Digest.SHA384
                .digest(baseJws.jwsHeader.certificateChain!!.leaf.encodeToDer())
                .encodeToString(Base64UrlStrict)

            val patchedJws = baseJws.patchHeader {
                put("x5t#o", buildJsonObject {
                    put("digAlg", "S384")
                    put("digVal", validB64Url)
                })
            }

            jadesVerifier(patchedJws).isSuccess shouldBe true
        }

        test("JAdES verification fails if x5t#o is present but x5c chain is missing") {
            val signed = it.signJwt(JwsContentTypeConstants.JWT, it.randomPayload.encodeToByteArray(), ByteArraySerializer()).getOrThrow()

            // Call .patchHeader on .jws
            val patchedJws = signed.jws.patchHeader {
                put("x5t#o", buildJsonObject {
                    put("digAlg", "S384")
                    put("digVal", "dummyValue")
                })
            }

            shouldThrowAny { jadesVerifier(patchedJws).getOrThrow() }
        }

        test("JAdES verification fails if forbidden sha-256 algorithm is specified") {
            val keyWithCert = EphemeralKeyWithSelfSignedCert()
            val signed = SignJwt<ByteArray>(keyWithCert, JwsHeaderCertOrJwk())(
                JwsContentTypeConstants.JWT,
                it.randomPayload.encodeToByteArray(),
                ByteArraySerializer()
            ).getOrThrow()

            val patchedJws = signed.jws.patchHeader {
                put("x5t#o", buildJsonObject {
                    put("digAlg", "S256")
                    put("digVal", "dummyValue")
                })
            }

            shouldThrowAny { jadesVerifier(patchedJws).getOrThrow() }
        }

        test("JAdES verification fails if certificate thumbprint does not match digVal") {
            val keyWithCert = EphemeralKeyWithSelfSignedCert()
            val signed = SignJwt<ByteArray>(keyWithCert, JwsHeaderCertOrJwk())(
                JwsContentTypeConstants.JWT,
                it.randomPayload.encodeToByteArray(),
                ByteArraySerializer()
            ).getOrThrow()

            val patchedJws = signed.jws.patchHeader {
                put("x5t#o", buildJsonObject {
                    put("digAlg", "S384")
                    put("digVal", "invalidMismatchedThumbprint")
                })
            }

            shouldThrowAny { jadesVerifier(patchedJws).getOrThrow() }
        }

        test("JAdES verification skips validation and succeeds if x5t#o parameter is absent") {
            val signed = it.signJwt(JwsContentTypeConstants.JWT, it.randomPayload.encodeToByteArray(), ByteArraySerializer()).getOrThrow()

            jadesVerifier(signed.jws).isSuccess shouldBe true
        }
    }
}

/**
 * Mutates a serialized JWS string by injecting custom parameters directly into the unverified JSON header block.
 * NOTE: This deliberately invalidates the cryptographic signature. Use for testing only.
 */
fun JwsCompact.patchHeader(patcher: kotlinx.serialization.json.JsonObjectBuilder.() -> Unit): JwsCompact {
    val rawHeaderJson = joseCompliantSerializer.decodeFromString<JsonObject>(plainProtectedHeader.decodeToString())

    val updatedHeaderJson = buildJsonObject {
        rawHeaderJson.forEach { (key, value) -> put(key, value) }
        patcher()
    }

    val updatedHeaderB64 = joseCompliantSerializer
        .encodeToString(JsonObject.serializer(), updatedHeaderJson)
        .encodeToByteArray()
        .encodeToString(Base64UrlStrict)

    val parts = this.toString().split('.')
    val newJwsStr = "$updatedHeaderB64.${parts[1]}.${parts[2]}"

    return JwsCompact(newJwsStr)
}

/**
 * Identify [KeyMaterial] with it's [KeyMaterial.identifier] set in [JwsHeader.keyId],
 * and URL set in[JwsHeader.jsonWebKeySetUrl].
 */
class JwsHeaderJwksUrl(val jsonWebKeySetUrl: String) : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(
        it: JwsHeader,
        keyMaterial: KeyMaterial,
    ) = it.copy(keyId = keyMaterial.identifier, jsonWebKeySetUrl = jsonWebKeySetUrl)
}
