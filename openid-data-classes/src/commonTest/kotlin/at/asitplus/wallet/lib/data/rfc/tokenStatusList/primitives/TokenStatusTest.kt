package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

val TokenStatusTest by matrixSuite {
    "argument validation" - {
        data((listOf(
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
            }).values) test { (status, expected) ->
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