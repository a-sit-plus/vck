package at.asitplus.wallet.lib

import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.nulls.shouldNotBeNull
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
