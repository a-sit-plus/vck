package at.asitplus.wallet.lib.jws

import at.asitplus.wallet.lib.jws.JwsExtensions.ensureSize
import at.asitplus.testballoon.matrix.matrixSuite
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.aroundEachTest
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveMinLength
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey

val JsonWebKeyJvmTest by matrixSuite {

    lateinit var ecCurve: EcCurve
    lateinit var keyPair: KeyPair


    testSuite("tests", testConfig = TestConfig.aroundEachTest { action ->
        ecCurve = EcCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        action()
    }) {
        "JWK can be created from Coordinates and recreated" {
            val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
            val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
            val jsonWebKey = JsonWebKey.fromCoordinates(JwkType.EC, ecCurve, xFromBc, yFromBc)

            jsonWebKey.shouldNotBeNull()
            jsonWebKey.x shouldBe xFromBc
            jsonWebKey.y shouldBe yFromBc
            jsonWebKey.keyId.shouldNotBeNull()
            jsonWebKey.keyId shouldHaveMinLength 32

            run {
                val recreatedJwk = JsonWebKey.fromKeyId(jsonWebKey.keyId!!)
                recreatedJwk.shouldNotBeNull()
                recreatedJwk.keyId shouldBe jsonWebKey.keyId
                recreatedJwk.x shouldBe jsonWebKey.x
                recreatedJwk.y shouldBe jsonWebKey.y
            }
        }

        "JWK can be created from ANSI X962 and recreated" {
            val xFromBc = (keyPair.public as ECPublicKey).w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
            val yFromBc = (keyPair.public as ECPublicKey).w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
            val ansiX962 = byteArrayOf(0x04) + xFromBc + yFromBc
            val jsonWebKey = JsonWebKey.fromAnsiX963Bytes(JwkType.EC, EcCurve.SECP_256_R_1, ansiX962)

            jsonWebKey.shouldNotBeNull()
            jsonWebKey.x shouldBe xFromBc
            jsonWebKey.y shouldBe yFromBc
            jsonWebKey.keyId.shouldNotBeNull()
            jsonWebKey.keyId shouldHaveMinLength 32
            jsonWebKey.toAnsiX963ByteArray().getOrThrow() shouldBe ansiX962

            run {
                val recreatedJwk = JsonWebKey.fromKeyId(jsonWebKey.keyId!!)
                recreatedJwk.shouldNotBeNull()
                recreatedJwk.keyId shouldBe jsonWebKey.keyId
                recreatedJwk.x shouldBe jsonWebKey.x
                recreatedJwk.y shouldBe jsonWebKey.y
                jsonWebKey.toAnsiX963ByteArray().getOrThrow() shouldBe ansiX962
            }
        }
    }
}
