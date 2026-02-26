package at.asitplus.wallet.lib

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import okio.Buffer
import okio.buffer
import okio.deflate
import okio.inflate
import kotlin.random.Random

val DefaultZlibServiceOkioInteropTest by testSuite {
    "ours compressed data inflates with okio" {
        val service = DefaultZlibService()
        val input = Random.nextBytes(2048)

        val oursCompressed = service.compress(input).shouldNotBeNull()
        okioInflate(oursCompressed) shouldBe input
    }

    "okio compressed data inflates with our implementation" {
        val service = DefaultZlibService()
        val input = Random.nextBytes(2048)

        val okioCompressed = okioDeflate(input)
        service.decompress(okioCompressed) shouldBe input
    }

    "both parsers decode each other's zlib streams" {
        val service = DefaultZlibService()
        val input = ("interop ".repeat(128) + "zlib/okio").encodeToByteArray()

        val oursCompressed = service.compress(input).shouldNotBeNull()
        val okioCompressed = okioDeflate(input)

        okioInflate(oursCompressed) shouldBe input
        service.decompress(okioCompressed) shouldBe input
    }

    "dynamic literal-only block with zero distance table is accepted" {
        val service = DefaultZlibService()
        val literalOnlyDynamicBlock = buildLiteralOnlyDynamicZlibStream()

        // Sanity-check the handcrafted stream with an independent decoder first.
        okioInflate(literalOnlyDynamicBlock) shouldBe ByteArray(0)
        service.decompress(literalOnlyDynamicBlock) shouldBe ByteArray(0)
    }

    "empty payload round-trip works both directions" {
        val service = DefaultZlibService()
        val empty = ByteArray(0)

        val oursCompressed = service.compress(empty).shouldNotBeNull()
        okioInflate(oursCompressed) shouldBe empty
        service.decompress(oursCompressed) shouldBe empty

        val okioCompressed = okioDeflate(empty)
        service.decompress(okioCompressed) shouldBe empty
        okioInflate(okioCompressed) shouldBe empty
    }

    "zero-length compressed input is rejected by our inflater" {
        val service = DefaultZlibService()
        service.decompress(ByteArray(0)).shouldBeNull()
    }

    "truncated zlib stream is rejected by our inflater" {
        val service = DefaultZlibService()
        val valid = service.compress(Random.nextBytes(64)).shouldNotBeNull()
        service.decompress(valid.dropLast(2).toByteArray()).shouldBeNull()
    }
}

private fun okioDeflate(input: ByteArray): ByteArray {
    val compressed = Buffer()
    val sink = compressed.deflate().buffer()
    try {
        sink.write(input)
    } finally {
        sink.close()
    }
    return compressed.readByteArray()
}

private fun okioInflate(input: ByteArray): ByteArray {
    val compressed = Buffer().write(input)
    val source = compressed.inflate().buffer()
    return try {
        source.readByteArray()
    } finally {
        source.close()
    }
}

private fun buildLiteralOnlyDynamicZlibStream(): ByteArray {
    val bitWriter = BitWriter()

    // BFINAL=1, BTYPE=10 (dynamic Huffman)
    bitWriter.writeBits(value = 1, count = 1)
    bitWriter.writeBits(value = 0b10, count = 2)

    // HLIT=2 -> 259 literal/length code lengths (257 + 2)
    // HDIST=0 -> 1 distance code length
    // HCLEN=14 -> 18 code-length code lengths (4 + 14)
    bitWriter.writeBits(value = 2, count = 5)
    bitWriter.writeBits(value = 0, count = 5)
    bitWriter.writeBits(value = 14, count = 4)

    // Code-length alphabet lengths in RFC1951 read order (first 18 entries):
    // [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1]
    // Non-zero symbols:
    // - 17 -> bit length 2
    // - 18 -> bit length 1
    // -  1 -> bit length 2
    intArrayOf(0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2).forEach {
        bitWriter.writeBits(value = it, count = 3)
    }

    // Literal/length + distance code lengths:
    // 256x zero, then EOB symbol(256)=1, then three zeroes (symbols 257, 258, dist0).
    // Using code-length codes:
    // - 18 (repeat zero 11..138), code = 0 (1 bit), extra 7 bits
    // -  1 (literal code length 1), code = 01 (2 bits)
    // - 17 (repeat zero 3..10), code = 11 (2 bits), extra 3 bits
    bitWriter.writeBits(value = 0b0, count = 1) // 18
    bitWriter.writeBits(value = 127, count = 7) // 138 zeros
    bitWriter.writeBits(value = 0b0, count = 1) // 18
    bitWriter.writeBits(value = 107, count = 7) // 118 zeros
    bitWriter.writeBits(value = 0b01, count = 2) // 1
    bitWriter.writeBits(value = 0b11, count = 2) // 17
    bitWriter.writeBits(value = 0, count = 3) // 3 zeros

    // Encoded data: EOB only (symbol 256), code = 0 (1 bit)
    bitWriter.writeBits(value = 0, count = 1)

    val deflatePayload = bitWriter.toByteArray()
    val zlibHeader = byteArrayOf(0x78.toByte(), 0x9C.toByte())
    val adler32OfEmpty = byteArrayOf(0x00, 0x00, 0x00, 0x01)
    return zlibHeader + deflatePayload + adler32OfEmpty
}

private class BitWriter {
    private val output = ArrayList<Byte>()
    private var currentByte = 0
    private var bitOffset = 0

    fun writeBits(value: Int, count: Int) {
        repeat(count) { bit ->
            val nextBit = (value ushr bit) and 0x01
            currentByte = currentByte or (nextBit shl bitOffset)
            bitOffset++
            if (bitOffset == 8) {
                output += currentByte.toByte()
                currentByte = 0
                bitOffset = 0
            }
        }
    }

    fun toByteArray(): ByteArray {
        if (bitOffset > 0) {
            output += currentByte.toByte()
            currentByte = 0
            bitOffset = 0
        }
        return output.toByteArray()
    }
}
