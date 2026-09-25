package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val TaggedCborBytesListSerializerTest by matrixSuite {
    val values = TaggedCborBytesList(
        listOf(byteArrayOf(0xA0.toByte()), byteArrayOf(0x01, 0x02), byteArrayOf())
    )
    // [#6.24(h'a0'), #6.24(h'0102'), #6.24(h'')]
    val expected = byteArrayOf(
        0x83.toByte(),
        0xD8.toByte(), 0x18, 0x41, 0xA0.toByte(),
        0xD8.toByte(), 0x18, 0x42, 0x01, 0x02,
        0xD8.toByte(), 0x18, 0x40,
    )

    "serializes each byte string with CBOR tag 24 in list order" {
        coseCompliantSerializer.encodeToByteArray(values) shouldBe expected
    }

    "deserializes tagged byte strings without changing their contents or order" {
        val decoded = coseCompliantSerializer.decodeFromByteArray<TaggedCborBytesList>(expected)
        decoded shouldBe values
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe expected
    }

    "round-trips an empty list" {
        val empty = TaggedCborBytesList(emptyList())
        val encoded = coseCompliantSerializer.encodeToByteArray(empty)
        encoded shouldBe byteArrayOf(0x80.toByte())
        coseCompliantSerializer.decodeFromByteArray<TaggedCborBytesList>(encoded) shouldBe empty
    }
}
