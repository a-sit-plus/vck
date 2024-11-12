package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.josef.*
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class ValidatorSdJwtBindingTest : FreeSpec({

    lateinit var key: KeyMaterial

    beforeEach {
        key = EphemeralKeyWithoutCert()
    }

    "with jwk" {
        val claim = ConfirmationClaim(jsonWebKey = key.jsonWebKey)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKey = key.jsonWebKey)
        val jws = JwsSigned(header, byteArrayOf(), CryptoSignature.RSAorHMAC(byteArrayOf()), byteArrayOf())

        DefaultVerifierJwsService().verifyConfirmationClaim(claim, jws) shouldBe true
    }

    "with jku and kid, because there are two keys" {
        val jku = "https://example.com/" + uuid4().toString()
        val kid = uuid4().toString()
        val claim = ConfirmationClaim(jsonWebKeySetUrl = jku, keyId = kid)
        val randomSecondKey = EphemeralKeyWithoutCert().jsonWebKey.copy(keyId = uuid4().toString())
        val keySet = JsonWebKeySet(listOf(key.jsonWebKey.copy(keyId = kid), randomSecondKey))
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKeySetUrl = jku, keyId = kid)
        val jws = JwsSigned(header, byteArrayOf(), CryptoSignature.RSAorHMAC(byteArrayOf()), byteArrayOf())

        DefaultVerifierJwsService(jwkSetRetriever = { keySet }).verifyConfirmationClaim(claim, jws) shouldBe true
    }

    "with jku, but without kid, because there is only one key" {
        val jku = "https://example.com/" + uuid4().toString()
        val claim = ConfirmationClaim(jsonWebKeySetUrl = jku)
        val keySet = JsonWebKeySet(listOf(key.jsonWebKey))
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKeySetUrl = jku)
        val jws = JwsSigned(header, byteArrayOf(), CryptoSignature.RSAorHMAC(byteArrayOf()), byteArrayOf())

        DefaultVerifierJwsService(jwkSetRetriever = { keySet }).verifyConfirmationClaim(claim, jws) shouldBe true
    }

    "with jwkThumbprint" {
        val claim = ConfirmationClaim(jsonWebKeyThumbprint = key.jsonWebKey.jwkThumbprint)
        val header = JwsHeader(algorithm = JwsAlgorithm.ES256, jsonWebKey = key.jsonWebKey)
        val jws = JwsSigned(header, byteArrayOf(), CryptoSignature.RSAorHMAC(byteArrayOf()), byteArrayOf())

        DefaultVerifierJwsService().verifyConfirmationClaim(claim, jws) shouldBe true
    }

})