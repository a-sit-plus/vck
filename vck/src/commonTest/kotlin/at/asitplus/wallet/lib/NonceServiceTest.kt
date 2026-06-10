package at.asitplus.wallet.lib

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty

val NonceServiceTest by matrixSuite {

    test("nonce lifecycle is tracked") {
        val service = DefaultNonceService()

        val nonce = service.provideNonce()
        nonce.shouldNotBeEmpty()

        service.verifyNonce(nonce) shouldBe true
        service.verifyAndRemoveNonce(nonce) shouldBe true
        service.verifyNonce(nonce) shouldBe false
    }
}
