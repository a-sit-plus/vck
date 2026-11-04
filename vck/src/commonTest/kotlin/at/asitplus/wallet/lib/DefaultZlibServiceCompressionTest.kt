package at.asitplus.wallet.lib

import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListView
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusBitSize
import at.asitplus.wallet.lib.extensions.toStatusList
import at.asitplus.wallet.lib.extensions.toView
import io.kotest.matchers.ints.shouldBeLessThan
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.element
import io.kotest.property.arbitrary.positiveInt
import okio.Buffer
import okio.buffer
import okio.inflate
import kotlin.random.Random

val DefaultZlibServiceCompressionTest by matrixSuite {
    "repetitive data inflates with okio and our implementation" - {
        val fewBytes = Arb.element(0x00.toByte(), 0x01.toByte(), 0x55.toByte(), 0xFF.toByte())
        property(Arb.byteArray(Arb.positiveInt(4096), fewBytes), iterations = 128) test { input ->
            val service = DefaultZlibService()

            val compressed = service.compress(input).shouldNotBeNull()
            okioInflate(compressed) shouldBe input
            service.decompress(compressed) shouldBe input
        }
    }

    "known zlib stream for 16 zero bytes" {
        // Fixed Huffman block: literal 0, length 15 (symbol 267, extra bit 0) at distance 1 (code 0), end of block.
        // Trailer: ADLER32 of 16 zero bytes, s2 = 16, s1 = 1.
        DefaultZlibService().compress(ByteArray(16)) shouldBe "789c6340030000100001".hexToByteArray()
    }

    "inputs shorter than a match round-trip" {
        val service = DefaultZlibService()
        listOf(byteArrayOf(0), byteArrayOf(0, 0), byteArrayOf(1, 2)).forEach { input ->
            val compressed = service.compress(input).shouldNotBeNull()

            okioInflate(compressed) shouldBe input
            service.decompress(compressed) shouldBe input
        }
    }

    "empty 1-bit status list of 131072 entries compresses to a fixed Huffman block" {
        val input = ByteArray(16384)

        val compressed = DefaultZlibService().compress(input).shouldNotBeNull()

        // BFINAL=1, BTYPE=01 in the lowest three bits of the first DEFLATE byte.
        (compressed[2].toInt() and 0b111) shouldBe 0b011
        compressed.size shouldBeLessThan 200
        okioInflate(compressed) shouldBe input
    }

    "random data falls back to stored blocks" {
        val input = Random(42).nextBytes(4096)

        val compressed = DefaultZlibService().compress(input).shouldNotBeNull()

        // BFINAL=1, BTYPE=00 in the lowest three bits of the first DEFLATE byte.
        (compressed[2].toInt() and 0b111) shouldBe 0b001
        // ZLIB header, one stored block header, the data, ADLER32.
        compressed.size shouldBe 2 + 5 + input.size + 4
        okioInflate(compressed) shouldBe input
    }

    "back-references reach across the whole window" {
        val half = Random(7).nextBytes(32768)
        val input = half + half

        val compressed = DefaultZlibService().compress(input).shouldNotBeNull()

        // The first half costs about 8.4 bits per byte as literals, the second one only back-references.
        compressed.size shouldBeLessThan 36000
        okioInflate(compressed) shouldBe input
        DefaultZlibService().decompress(compressed) shouldBe input
    }

    "matches of the maximum length follow each other" {
        val input = ByteArray(258 * 4 + 1) { 0x55 }

        val compressed = DefaultZlibService().compress(input).shouldNotBeNull()

        okioInflate(compressed) shouldBe input
    }

    "output only depends on the input" {
        val input = ByteArray(16384).also { it[1000] = 0x01; it[9000] = 0x10 }

        DefaultZlibService().compress(input) shouldBe DefaultZlibService().compress(input)
    }

    "status lists round-trip" {
        val random = Random(1)
        listOf(
            TokenStatusBitSize.ONE to listOf(TokenStatus.Valid, TokenStatus.Invalid),
            TokenStatusBitSize.TWO to listOf(TokenStatus.Valid, TokenStatus.Invalid, TokenStatus.Suspended),
        ).forEach { (bitSize, statuses) ->
            val view = StatusListView.fromTokenStatuses(
                List(100_000) { if (random.nextInt(100) == 0) statuses.random(random) else TokenStatus.Valid },
                bitSize,
            )

            val statusList = view.toStatusList(DefaultZlibService(), null)

            statusList.compressed.size shouldBeLessThan view.uncompressed.size / 4
            statusList.toView(DefaultZlibService()) shouldBe view
        }
    }
}

private fun String.hexToByteArray(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun okioInflate(input: ByteArray): ByteArray {
    val compressed = Buffer().write(input)
    val source = compressed.inflate().buffer()
    return try {
        source.readByteArray()
    } finally {
        source.close()
    }
}
