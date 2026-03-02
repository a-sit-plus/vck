package at.asitplus.wallet.lib

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

private val knownPayload: ByteArray =
    "ZLIB deflate/inflate regression test payload. ".repeat(6).encodeToByteArray() +
        ByteArray(64) { it.toByte() }

private val knownCompressedPayload: ByteArray =
    "789c8bf2f1745248494dcb492c49d5cfcc03d30a45a9e945a9c5c599f9790a25a9c5250a05899539f989297a0a51234235032313330b2b1b3b072717370f2f1fbf80a090b088a898b884a494b48cac9cbc82a292b28aaa9aba86a696b68eae9ebe81a191b189a999b985a595b58dad9d3d006eea6cc7"
        .hexToByteArray()

val DefaultZlibServiceTest by testSuite {
    "compress/decompress round-trip" {
        val service = DefaultZlibService()
        val input = ("Round-trip ".repeat(64) + "zlib regression").encodeToByteArray()

        val compressed = service.compress(input).shouldNotBeNull()
        service.decompress(compressed) shouldBe input
    }

    "decompresses known zlib payload" {
        val service = DefaultZlibService()

        service.decompress(knownCompressedPayload) shouldBe knownPayload
    }

    "compression writes valid RFC1950 envelope" {
        val service = DefaultZlibService()
        val payload = ByteArray(1024) { (it * 31).toByte() }

        val compressed = service.compress(payload).shouldNotBeNull()
        val cmf = compressed[0].toUByte().toInt()
        val flg = compressed[1].toUByte().toInt()

        (cmf and 0x0F) shouldBe 0x08
        (((cmf shl 8) or flg) % 31) shouldBe 0
        readUInt32BE(compressed, compressed.size - 4) shouldBe adler32(payload)
    }
}

private fun String.hexToByteArray(): ByteArray =
    chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun readUInt32BE(data: ByteArray, offset: Int): UInt =
    ((data[offset].toUInt() and 0xFFu) shl 24) or
        ((data[offset + 1].toUInt() and 0xFFu) shl 16) or
        ((data[offset + 2].toUInt() and 0xFFu) shl 8) or
        (data[offset + 3].toUInt() and 0xFFu)

private fun adler32(data: ByteArray): UInt {
    var s1 = 1u
    var s2 = 0u
    data.forEach {
        s1 = (s1 + it.toUByte().toUInt()) % 65521u
        s2 = (s2 + s1) % 65521u
    }
    return (s2 shl 16) or s1
}
