package at.asitplus.wallet.lib.data.rfc1950

import at.asitplus.wallet.lib.data.rfc1950.primitives.Nibble
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.shouldBe

class CompressionMethodAndFlagsTest : FreeSpec({
    "check properties" - {
        withData(
            (0..Nibble.MAX_VALUE).map {
                it.toByte()
            },
        ) {
            CompressionMethodAndFlags(it).compressionMethod.value shouldBe it

            val value = it.toInt().shl(4).toUByte().toByte()
            CompressionMethodAndFlags(value).compressionInfo.value shouldBe it
        }
    }
})