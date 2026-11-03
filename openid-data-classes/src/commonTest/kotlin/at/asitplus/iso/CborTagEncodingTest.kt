package at.asitplus.iso

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

val CborTagEncodingTest by matrixSuite {
    "CBOR tag heads use the shortest encoding around the 24 boundary" {
        val item = byteArrayOf(0x84.toByte())

        item.wrapInCborTag(18).map(Byte::toUByte) shouldBe listOf(0xd2u.toUByte(), 0x84u.toUByte())
        item.wrapInCborTag(23).map(Byte::toUByte) shouldBe listOf(0xd7u.toUByte(), 0x84u.toUByte())
        item.wrapInCborTag(24).map(Byte::toUByte) shouldBe listOf(0xd8u.toUByte(), 0x18u.toUByte(), 0x84u.toUByte())
        item.wrapInCborTag(0xff.toByte()).map(Byte::toUByte) shouldBe
            listOf(0xd8u.toUByte(), 0xffu.toUByte(), 0x84u.toUByte())

        item.wrapInCborTag(18).stripCborTag(18).toList() shouldBe item.toList()
        item.wrapInCborTag(24).stripCborTag(24).toList() shouldBe item.toList()
    }
}
