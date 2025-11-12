package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlin.random.Random

val JwsServiceTest by testSuite {


    withFixtureGenerator {
        object {
            val keyId = Random.nextBytes(16).encodeToString(Base64())
            val keyMaterial = EphemeralKeyWithoutCert(customKeyId = keyId)
            val signJwt = SignJwt<ByteArray>(keyMaterial, JwsHeaderCertOrJwk())
            val verifierJwsService = VerifyJwsObject()
            val randomPayload = uuid4().toString()

        }
    } - {
        "signed object with bytes can be verified" {
            val payload = it.randomPayload.encodeToByteArray()
            val signed = it.signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()
            it.verifierJwsService(signed).getOrThrow()
        }

        "Object can be reconstructed" {
            val payload = it.randomPayload.encodeToByteArray()
            val signed =
                it.signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow().serialize()

            val parsed = JwsSigned.deserialize<ByteArray>(ByteArraySerializer(), signed).getOrThrow()
            parsed.serialize() shouldBe signed
            parsed.payload shouldBe payload
            it.verifierJwsService(parsed).getOrThrow()
        }

        "signed object can be verified" {
            val payload = it.randomPayload.encodeToByteArray()
            val signed = it.signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()
            it.verifierJwsService(signed).getOrThrow()
        }

        "signed object with jsonWebKey can be verified" {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwk())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()
            it.verifierJwsService(signed).getOrThrow()
        }

        "signed object with kid from jku can be verified" {
            val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwksUrl(jku))
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()
            val validKey = it.keyMaterial.jsonWebKey
            val jwkSetRetriever = JwkSetRetrieverFunction { JsonWebKeySet(keys = listOf(validKey)) }
            VerifyJwsObject(jwkSetRetriever = jwkSetRetriever)(signed).getOrThrow()
        }

        "signed object with kid from jku, returning invalid key, can not be verified" {
            val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderJwksUrl(jku))
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()
            val invalidKey = EphemeralKeyWithoutCert().jsonWebKey
            val jwkSetRetriever = JwkSetRetrieverFunction { JsonWebKeySet(keys = listOf(invalidKey)) }
            shouldThrowAny { VerifyJwsObject(jwkSetRetriever = jwkSetRetriever)(signed).getOrThrow() }
        }

        "signed object without public key in header can not be verified" {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderNone())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

        shouldThrowAny { VerifyJwsObject()(signed).getOrThrow() }
    }

        "signed object without public key in header, but retrieved out-of-band can be verified" {
            val signer = SignJwt<String>(it.keyMaterial, JwsHeaderNone())
            val signed = signer(null, it.randomPayload, String.serializer()).getOrThrow()

            val publicKeyLookup = PublicJsonWebKeyLookup { jwsSigned -> setOf(it.keyMaterial.jsonWebKey) }
            VerifyJwsObject(publicKeyLookup = publicKeyLookup)(signed).getOrThrow()
        }

        "encrypted object can be decrypted" {
            val encrypterKey = EphemeralKeyWithoutCert()
            val encrypter = EncryptJwe(encrypterKey)
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
    }
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

/** Identify [KeyMaterial] with it's [KeyMaterial.jsonWebKey] in [JwsHeader.jsonWebKey]. */
class JwsHeaderJwk : JwsHeaderIdentifierFun {
    override suspend operator fun invoke(it: JwsHeader, keyMaterial: KeyMaterial) =
        it.copy(jsonWebKey = keyMaterial.jsonWebKey)
}
