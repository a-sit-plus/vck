package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlin.random.Random

class JwsServiceTest : FreeSpec({

    lateinit var keyId: String
    lateinit var keyMaterial: KeyMaterial
    lateinit var signJwt: SignJwtFun<ByteArray>
    lateinit var verifierJwsService: VerifyJwsObjectFun
    lateinit var randomPayload: String

    beforeEach {
        keyId = Random.nextBytes(16).encodeToString(Base64())
        keyMaterial = EphemeralKeyWithoutCert(customKeyId = keyId)
        signJwt = SignJwt(keyMaterial, JwsHeaderCertOrJwk())
        verifierJwsService = VerifyJwsObject()
        randomPayload = uuid4().toString()
    }

    "signed object with bytes can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val signed = signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()

        val result = verifierJwsService(signed)
        result shouldBe true
    }

    "Object can be reconstructed" {
        val payload = randomPayload.encodeToByteArray()
        val signed = signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow().serialize()

        val parsed = JwsSigned.deserialize<ByteArray>(ByteArraySerializer(), signed).getOrThrow()
        parsed.serialize() shouldBe signed
        parsed.payload shouldBe payload

        val result = verifierJwsService(parsed)
        result shouldBe true
    }

    "signed object can be verified" {
        val payload = randomPayload.encodeToByteArray()
        val signed = signJwt(JwsContentTypeConstants.JWT, payload, ByteArraySerializer()).getOrThrow()

        val result = verifierJwsService(signed)
        result shouldBe true
    }

    "signed object with jsonWebKey can be verified" {
        val signer = SignJwt<String>(keyMaterial, JwsHeaderJwk())
        val signed = signer(null, randomPayload, String.serializer()).getOrThrow()

        val result = verifierJwsService(signed)
        result shouldBe true
    }

    "signed object with kid from jku can be verified" {
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val signer = SignJwt<String>(keyMaterial, JwsHeaderJwksUrl(jku))
        val signed = signer(null, randomPayload, String.serializer()).getOrThrow()
        val validKey = keyMaterial.jsonWebKey
        val jwkSetRetriever = JwkSetRetrieverFunction { JsonWebKeySet(keys = listOf(validKey)) }
        verifierJwsService = VerifyJwsObject(jwkSetRetriever = jwkSetRetriever)
        verifierJwsService(signed) shouldBe true
    }

    "signed object with kid from jku, returning invalid key, can not be verified" {
        val jku = "https://example.com/" + Random.nextBytes(16).encodeToString(Base64UrlStrict)
        val signer = SignJwt<String>(keyMaterial, JwsHeaderJwksUrl(jku))
        val signed = signer(null, randomPayload, String.serializer()).getOrThrow()
        val invalidKey = EphemeralKeyWithoutCert().jsonWebKey
        val jwkSetRetriever = JwkSetRetrieverFunction { JsonWebKeySet(keys = listOf(invalidKey)) }
        verifierJwsService = VerifyJwsObject(jwkSetRetriever = jwkSetRetriever)
        verifierJwsService(signed) shouldBe false
    }

    "signed object without public key in header can not be verified" {
        val signer = SignJwt<String>(keyMaterial, JwsHeaderNone())
        val signed = signer(null, randomPayload, String.serializer()).getOrThrow()

        verifierJwsService = VerifyJwsObject()
        verifierJwsService(signed) shouldBe false
    }

    "signed object without public key in header, but retrieved out-of-band can be verified" {
        val signer = SignJwt<String>(keyMaterial, JwsHeaderNone())
        val signed = signer(null, randomPayload, String.serializer()).getOrThrow()

        val publicKeyLookup = PublicJsonWebKeyLookup { setOf(keyMaterial.jsonWebKey) }
        verifierJwsService = VerifyJwsObject(publicKeyLookup = publicKeyLookup)
        verifierJwsService(signed) shouldBe true
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
                jsonWebKey = encrypterKey.jsonWebKey,
                type = "anything",
            ),
            randomPayload,
            decrypterKey.jsonWebKey,
        ).getOrThrow().serialize().shouldNotBeNull()

        val parsed = JweEncrypted.deserialize(encrypted).getOrThrow()

        decrypter(parsed).getOrThrow()
            .shouldNotBeNull()
            .payload shouldBe randomPayload
    }
})


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
