package at.asitplus.wallet.lib

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import okio.Buffer
import okio.Deflater
import okio.DeflaterSink

private fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "Hex string must have an even length." }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

private fun deflateRaw(input: ByteArray): ByteArray {
    val source = Buffer().write(input)
    val compressed = Buffer()
    val deflaterSink = DeflaterSink(compressed, Deflater(-1, true))
    try {
        deflaterSink.write(source, source.size)
    } finally {
        deflaterSink.close()
    }
    return compressed.readByteArray()
}

val DefaultZlibServiceTest by testSuite {
    val service = DefaultZlibService()

    "DefaultZlibService" - {
        "roundtrip works for empty, small and medium payloads" {
            val payloads = listOf(
                ByteArray(0),
                "hello world".encodeToByteArray(),
                ByteArray(4096) { (it % 251).toByte() },
            )

            payloads.forEach { payload ->
                val compressed = service.compress(payload)
                (compressed != null) shouldBe true

                val decompressed = service.decompress(compressed!!)
                (decompressed?.contentEquals(payload) == true) shouldBe true
            }
        }

        "decompresses legacy zlib vector from previous implementation" {
            val compressedHelloWorld = "789ccb48cdc9c95728cf2fca4901001a0b045d".hexToByteArray()
            val decompressed = service.decompress(compressedHelloWorld)

            (decompressed?.contentEquals("hello world".encodeToByteArray()) == true) shouldBe true
        }

        "rejects malformed CMF/FLG header" {
            val malformed = "789ccb48cdc9c95728cf2fca4901001a0b045d".hexToByteArray()
                .also { bytes -> bytes[1] = (bytes[1].toInt() xor 0x01).toByte() }

            service.decompress(malformed) shouldBe null
        }

        "rejects adler32 checksum mismatch" {
            val malformed = "789ccb48cdc9c95728cf2fca4901001a0b045d".hexToByteArray()
                .also { bytes -> bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte() }

            service.decompress(malformed) shouldBe null
        }

        "rejects raw DEFLATE without zlib wrapper" {
            val rawDeflate = deflateRaw("raw-deflate".encodeToByteArray())
            service.decompress(rawDeflate) shouldBe null
        }

        "rejects decompression output beyond configured limit" {
            val oversizedPayload = ByteArray(DefaultZlibService.MAX_DECOMPRESSED_SIZE.toInt() + 1) { 0x41 }
            val compressed = service.compress(oversizedPayload)
            (compressed != null) shouldBe true

            service.decompress(compressed!!) shouldBe null
        }
    }
}
