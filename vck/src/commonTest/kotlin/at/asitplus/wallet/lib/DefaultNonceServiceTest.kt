package at.asitplus.wallet.lib

import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

val DefaultNonceServiceTest by testSuite {

    test("verify is correct") {
        with(
            DefaultNonceService(
                lifetime = 20.milliseconds,
                sizeToCheckForExpiration = 1U
            )
        ) {
            val nonce = provideNonce()
            verifyNonce(nonce).shouldBeTrue()
            verifyNonce(uuid4().toString()).shouldBeFalse()
            delay(50.milliseconds)
            verifyNonce(nonce).shouldBeFalse()
            verifyNonce(uuid4().toString()).shouldBeFalse()
        }
    }

    test("verifyAndRemove is correct") {
        with(
            DefaultNonceService(
                lifetime = 20.milliseconds,
                sizeToCheckForExpiration = 1U
            )
        ) {
            val nonce = provideNonce()
            verifyAndRemoveNonce(nonce).shouldBeTrue()
            verifyAndRemoveNonce(uuid4().toString()).shouldBeFalse()
            delay(50.milliseconds)
            verifyNonce(nonce).shouldBeFalse()
            verifyAndRemoveNonce(uuid4().toString()).shouldBeFalse()
        }
    }

}
