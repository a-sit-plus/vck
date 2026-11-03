package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborArray
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborMapEntry
import net.orandja.obor.data.CborObject

@Serializable
private data class Payload(val first: String, val second: Int)

@Serializable
private data class Holder(
    @Serializable(with = ReserializableByteStringSerializer::class)
    val payload: ByteStringWrapper<Payload>,
)

val ReserializableByteStringSerializerTest by matrixSuite {

    val payload = Payload("first", 2)

    "serializes a decoded value again to the bytes it was decoded from" {
        val received = coseCompliantSerializer.encodeToByteArray(payload).withReversedKeys()
        val encoded = coseCompliantSerializer.encodeToByteArray(Holder(ByteStringWrapper(payload, received)))

        val decoded = coseCompliantSerializer.decodeFromByteArray<Holder>(encoded)

        decoded.payload.value shouldBe payload
        decoded.payload.serialized shouldBe received
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe encoded
    }

    "encodes the value of a wrapper without bytes" {
        val encoded = coseCompliantSerializer.encodeToByteArray(Holder(ByteStringWrapper(payload)))

        val decoded = coseCompliantSerializer.decodeFromByteArray<Holder>(encoded)

        decoded.payload.value shouldBe payload
        decoded.payload.serialized shouldBe coseCompliantSerializer.encodeToByteArray(payload)
        coseCompliantSerializer.encodeToByteArray(decoded) shouldBe encoded
    }
}

/** This encoded CBOR with the keys of all its maps reversed, which encodes the same value differently. */
private fun ByteArray.withReversedKeys(): ByteArray =
    Cbor.encodeToByteArray<CborObject>(Cbor.decodeFromByteArray<CborObject>(this).withReversedKeys())
        .also { it.contentEquals(this) shouldBe false }

private fun CborObject.withReversedKeys(): CborObject = when (this) {
    is CborMap -> CborObject.orderedMap(elements.asReversed().map { CborMapEntry(it.key, it.value.withReversedKeys()) })
    is CborArray -> CborArray(elements.map { it.withReversedKeys() }.toMutableList(), indefinite)
    else -> this
}
