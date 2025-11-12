package at.asitplus.wallet.lib.data.rfc1950

import at.asitplus.testballoon.*
import at.asitplus.wallet.lib.data.rfc1950.primitives.Nibble
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

val CompressionMethodAndFlagsTest by testSuite {
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
}