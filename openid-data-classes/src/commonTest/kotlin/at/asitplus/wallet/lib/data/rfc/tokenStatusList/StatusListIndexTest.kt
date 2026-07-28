package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

val StatusListIndexTest by matrixSuite {
    "negative status-list indices are rejected" {
        shouldThrow<IllegalArgumentException> {
            StatusListInfo("https://example.com/status", -1)
        }
        shouldThrow<IllegalArgumentException> {
            StatusListView(ByteArray(1), TokenStatusBitSize.ONE).getOrNull(-1)
        }
    }

    "Java constructor delegates to ULong" {
        val info = StatusListInfo("https://example.com/status", 1)
        info.index shouldBe 1UL
    }
}
