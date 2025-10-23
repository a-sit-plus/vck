package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

val TokenStatusTest by testSuite {
    "argument validation" - {
        withData(
            listOf(
                0u to true,
                1u to true,
                2u to true,
                3u to true,
                4u to true,
                15u to true,
                16u to true,
                127u to true,
                128u to true,
                255u to true,
                256u to false,
            ).associateBy {
                "${it.first} shouldbe ${if (it.second) "not " else ""} fine"
            }
        ) { (status, expected) ->
            if (expected) {
                shouldNotThrowAny {
                    TokenStatus(status)
                }
            } else {
                shouldThrow<IllegalArgumentException> {
                    TokenStatus(status)
                }
            }
        }
    }
}