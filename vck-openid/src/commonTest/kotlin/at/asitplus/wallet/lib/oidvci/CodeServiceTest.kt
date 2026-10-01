package at.asitplus.wallet.lib.oidvci

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.DefaultNonceService
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

val CodeServiceTest by matrixSuite {

    test("a code is valid exactly once") {
        val codeService = DefaultCodeService()
        val code = codeService.provideCode()

        codeService.verifyAndRemove(code) shouldBe true
        codeService.verifyAndRemove(code) shouldBe false
    }

    test("an unknown code is never valid") {
        DefaultCodeService().verifyAndRemove("not-a-code") shouldBe false
    }

    /**
     * Codes must be single-use even when a client races several redemptions of the same code
     * (RFC 6749 4.1.2), which a plain `MutableList` can not guarantee. All coroutines wait on one barrier so
     * they hit the store at the same time, and the whole thing is repeated to make the race likely to show.
     */
    test("concurrent redemptions of the same code succeed exactly once") {
        val codeService = DefaultCodeService()
        repeat(300) {
            val code = codeService.provideCode()
            val start = CompletableDeferred<Unit>()
            val successes = coroutineScope {
                (1..16).map {
                    async(Dispatchers.Default) {
                        start.await()
                        codeService.verifyAndRemove(code)
                    }
                }.also { start.complete(Unit) }.awaitAll()
            }.count { it }

            successes shouldBe 1
        }
    }

    test("codes expire with the lifetime of the underlying nonce service") {
        var now = Clock.System.now()
        val codeService = DefaultCodeService(
            DefaultNonceService(lifetime = 5.minutes, clock = object : Clock {
                override fun now(): Instant = now
            })
        )
        val code = codeService.provideCode()

        now += 6.minutes

        codeService.verifyAndRemove(code) shouldBe false
    }
}
