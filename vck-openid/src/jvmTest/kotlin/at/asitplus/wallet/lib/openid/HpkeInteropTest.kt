package at.asitplus.wallet.lib.openid

import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.asymmetric.HPKE
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlin.random.Random
import org.bouncycastle.crypto.hpke.HPKE as BcHpke

/**
 * Verifies that signum's HPKE (RFC 9180) implementation is interoperable with Bouncy Castle's,
 * for the cipher suite required by ISO/IEC 18013-7 Annex C (as used in [DcApiVerifier]):
 * DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
 */
val HpkeInteropTest by matrixSuite {

    val signumHpke = HPKE(HPKE.KEM.DHKEM_P256_HKDF_SHA256, HPKE.KDF.HKDF_SHA256, HPKE.AEAD.AES_128_GCM)
    val bcHpke = BcHpke(BcHpke.mode_base, BcHpke.kem_P256_SHA256, BcHpke.kdf_HKDF_SHA256, BcHpke.aead_AES_GCM128)

    val plaintext = Random.nextBytes(257)
    val info = Random.nextBytes(64)
    val aad = Random.nextBytes(32)

    test("signum seals, Bouncy Castle opens") {
        val recipientKeyPair = bcHpke.generatePrivateKey()
        val recipientPublicKey = signumHpke.kem.DeserializePublicKey(
            bcHpke.serializePublicKey(recipientKeyPair.public)
        )

        val sealed = signumHpke.SealBase(pkR = recipientPublicKey, info = info, aad = aad, pt = plaintext)

        bcHpke.open(
            sealed.encapsulatedSecret, recipientKeyPair, info, aad, sealed.ciphertext,
            null, null, null,
        ) shouldBe plaintext
    }

    test("Bouncy Castle seals, signum opens") {
        val recipientKey = KeyAgreementPrivateValue.ECDH.Ephemeral(ECCurve.SECP_256_R_1).getOrThrow()
        val recipientPublicKey = bcHpke.deserializePublicKey(
            signumHpke.kem.SerializePublicKey(recipientKey.publicValue)
        )

        val sealed = bcHpke.seal(recipientPublicKey, info, aad, plaintext, null, null, null)
        val ciphertext = sealed[0]
        val encapsulatedSecret = sealed[1]

        signumHpke.OpenBase(
            enc = encapsulatedSecret,
            skR = recipientKey,
            info = info,
            aad = aad,
            ct = ciphertext,
        ) shouldBe plaintext
    }
}
