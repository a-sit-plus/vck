package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val EphemeralEncryptionKeyServiceTest by matrixSuite {

    test("keys are synchronized through the store, and consumable exactly once") {
        // the instance creating the authentication request is not the one receiving the response, e.g. in a cluster
        val store = DefaultMapStore<String, String>()
        val requestSide = EphemeralEncryptionKeyService(store)
        val responseSide = EphemeralEncryptionKeyService(store)

        val created = requestSide.createKey()
        val recovered = responseSide.consumeKey(created.identifier).shouldNotBeNull()

        recovered.identifier shouldBe created.identifier
        recovered.publicKey shouldBe created.publicKey
        // single-use, matching the lifecycle of the request the key belongs to
        responseSide.consumeKey(created.identifier).shouldBeNull()
    }

    test("every request gets its own key, optionally identified by something else than its own key id") {
        val service = EphemeralEncryptionKeyService()

        service.createKey().publicKey shouldNotBe service.createKey().publicKey

        val state = "state-${uuid4()}"
        service.createKey(state).identifier shouldBe state
        service.consumeKey(state).shouldNotBeNull().identifier shouldBe state
        service.consumeKey("never issued").shouldBeNull()
    }

    test("a recovered key agrees on the same secret as the key that was created") {
        val store = DefaultMapStore<String, String>()
        val created = EphemeralEncryptionKeyService(store).createKey()
        val recovered = EphemeralEncryptionKeyService(store).consumeKey(created.identifier).shouldNotBeNull()

        val wallet = EphemeralKeyWithoutCert()
        val secretFromRecoveredKey = (recovered.getUnderLyingSigner() as Signer.ECDSA)
            .keyAgreement(wallet.publicKey as CryptoPublicKey.EC).getOrThrow()
        val secretFromWalletSide = (wallet.getUnderLyingSigner() as Signer.ECDSA)
            .keyAgreement(created.publicKey as CryptoPublicKey.EC).getOrThrow()

        secretFromRecoveredKey shouldBe secretFromWalletSide
    }
}
