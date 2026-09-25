package at.asitplus.iso

import at.asitplus.dcapi.DCAPIHandover
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToByteArray

val ReaderAuthenticationAllSerializerTest by matrixSuite {
    val transcript = SessionTranscript.forDcApi(DCAPIHandover(DCAPIHandover.TYPE_DCAPI, ByteArray(32)))
    val itemsRequestBytesAll = TaggedCborBytesList(listOf(byteArrayOf(0xA0.toByte())))
    // ["ReaderAuthenticationAll", SessionTranscript, ItemsRequestBytesAll, ...] without the last element
    val prefix = byteArrayOf(0x84.toByte()) +
            coseCompliantSerializer.encodeToByteArray("ReaderAuthenticationAll") +
            coseCompliantSerializer.encodeToByteArray(transcript) +
            coseCompliantSerializer.encodeToByteArray(itemsRequestBytesAll)

    "absent DeviceRequestInfoBytes is encoded as untagged null (ISO/IEC 18013-5, 12.5)" {
        val value = ReaderAuthenticationAll("ReaderAuthenticationAll", transcript, itemsRequestBytesAll, null)
        val expected = prefix + byteArrayOf(0xF6.toByte())

        coseCompliantSerializer.encodeToByteArray(value) shouldBe expected
    }

    "present DeviceRequestInfoBytes is encoded as tag-24 byte string" {
        val value = ReaderAuthenticationAll(
            "ReaderAuthenticationAll",
            transcript,
            itemsRequestBytesAll,
            byteArrayOf(0xA1.toByte(), 0x00, 0x01)
        )
        // #6.24(h'a10001')
        val expected = prefix + byteArrayOf(0xD8.toByte(), 0x18, 0x43, 0xA1.toByte(), 0x00, 0x01)

        coseCompliantSerializer.encodeToByteArray(value) shouldBe expected
    }
}
