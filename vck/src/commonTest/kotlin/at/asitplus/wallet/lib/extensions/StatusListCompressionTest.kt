package at.asitplus.wallet.lib.extensions

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.random.Random

private class FakeZlibService(
    private val compressResult: ByteArray? = null,
    private val decompressResult: ByteArray? = byteArrayOf(0x5a, 0x6b),
) : ZlibService {
    override fun compress(input: ByteArray) = compressResult

    override fun decompress(input: ByteArray) = decompressResult
}

val StatusListCompressionTest by testSuite {
    "StatusList.toView" - {
        "uses decompressed bytes when available" {
            val compressed = Random.nextBytes(16)
            val decompressed = Random.nextBytes(16)
            val statusList = StatusList(
                compressed = compressed,
                statusBitSize = TokenStatusBitSize.ONE,
                aggregationUri = null,
            )

            val view = statusList.toView(FakeZlibService(decompressResult = decompressed))

            view.uncompressed shouldBe decompressed
            view.statusBitSize shouldBe TokenStatusBitSize.ONE
        }

        "falls back to compressed bytes when decompression fails" {
            val compressed = Random.nextBytes(16)
            val statusList = StatusList(
                compressed = compressed,
                statusBitSize = TokenStatusBitSize.TWO,
                aggregationUri = null,
            )

            val view = statusList.toView(FakeZlibService(decompressResult = null))

            view.uncompressed shouldBe compressed
            view.statusBitSize shouldBe TokenStatusBitSize.TWO
        }
    }

    "StatusListView.toStatusList" - {
        "uses compressed bytes when available" {
            val uncompressed = Random.nextBytes(16)
            val compressed = Random.nextBytes(16)
            val view = StatusListView(
                uncompressed = uncompressed,
                statusBitSize = TokenStatusBitSize.FOUR,
            )

            val statusList = view.toStatusList(
                zlibService = FakeZlibService(compressResult = compressed),
                statusListAggregationUrl = null,
            )

            statusList.compressed shouldBe compressed
            statusList.statusBitSize shouldBe TokenStatusBitSize.FOUR
        }

        "falls back to uncompressed bytes when compression fails" {
            val uncompressed = Random.nextBytes(16)
            val view = StatusListView(
                uncompressed = uncompressed,
                statusBitSize = TokenStatusBitSize.EIGHT,
            )

            val statusList = view.toStatusList(
                zlibService = FakeZlibService(),
                statusListAggregationUrl = null,
            )

            statusList.compressed shouldBe uncompressed
            statusList.statusBitSize shouldBe TokenStatusBitSize.EIGHT
        }
    }
}
