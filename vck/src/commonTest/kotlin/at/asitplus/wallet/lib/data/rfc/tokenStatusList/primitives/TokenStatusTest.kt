package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData

class TokenStatusTest : FreeSpec({
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
})