package at.asitplus.wallet.lib.jws

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.asn1.ensureSize
import at.asitplus.signum.indispensable.josef.JsonWebKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveMinLength
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey

class JsonWebKeyJvmTest : FreeSpec({

    lateinit var ecCurve: ECCurve
    lateinit var keyPair: KeyPair

    beforeTest {
        ecCurve = ECCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
    }

    "JWK can be created from Coordinates" - {
        val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val jsonWebKey = JsonWebKey.fromCoordinates(ecCurve, xFromBc, yFromBc).getOrThrow()

        jsonWebKey.x shouldBe xFromBc
        jsonWebKey.y shouldBe yFromBc
        jsonWebKey.jwkThumbprint.shouldNotBeNull()
        jsonWebKey.jwkThumbprint shouldHaveMinLength 32

        "it can be recreated" {
            val recreatedJwk = JsonWebKey.fromDid(jsonWebKey.didEncoded!!).getOrThrow()
            recreatedJwk.keyId shouldBe jsonWebKey.didEncoded!!
            recreatedJwk.x shouldBe jsonWebKey.x
            recreatedJwk.y shouldBe jsonWebKey.y
        }
    }

    "JWK can be created from ANSI X962" - {
        val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val ansiX962 = byteArrayOf(0x04) + xFromBc + yFromBc
        val jsonWebKey = JsonWebKey.fromCoordinates(ecCurve, xFromBc, yFromBc).getOrThrow()

        jsonWebKey.x shouldBe xFromBc
        jsonWebKey.y shouldBe yFromBc
        jsonWebKey.jwkThumbprint.shouldNotBeNull()
        jsonWebKey.jwkThumbprint shouldHaveMinLength 32
        jsonWebKey.toCryptoPublicKey().getOrThrow().iosEncoded shouldBe  ansiX962

        "it can be recreated" {
            val recreatedJwk = JsonWebKey.fromDid(jsonWebKey.didEncoded!!).getOrThrow()
            recreatedJwk.keyId shouldBe jsonWebKey.didEncoded
            recreatedJwk.x shouldBe jsonWebKey.x
            recreatedJwk.y shouldBe jsonWebKey.y
            jsonWebKey.toCryptoPublicKey().getOrThrow().iosEncoded shouldBe ansiX962
        }
    }

})
