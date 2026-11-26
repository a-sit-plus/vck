package at.asitplus.wallet.lib.agent

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val HolderKeyResolverTest by matrixSuite {

    test("single resolves its own key") {
        val key = EphemeralKeyWithoutCert()

        HolderKeyResolver.single(key).resolve(key.publicKey).getOrThrow() shouldBe key
    }

    test("single fails for any other key") {
        val key = EphemeralKeyWithoutCert()

        HolderKeyResolver.single(key).resolve(EphemeralKeyWithoutCert().publicKey).exceptionOrNull()
            .shouldNotBeNull().shouldBeInstanceOf<IllegalArgumentException>()
    }
}
