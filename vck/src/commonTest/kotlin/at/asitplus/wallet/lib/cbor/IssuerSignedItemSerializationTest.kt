package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.ItemValueDecoder
import at.asitplus.wallet.lib.iso.*
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.CompositeDecoder
import kotlin.random.Random
import kotlin.random.nextUInt

class IssuerSignedItemSerializationTest : FreeSpec({

    "!serialization with String" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = uuid4().toString(),
        )

        val serialized = item.serialize()
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized, "").getOrThrow()
        parsed shouldBe item
    }

    "!serialization with ByteArray" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = Random.nextBytes(32),
        )

        val serialized = item.serialize()
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")
        val parsed = IssuerSignedItem.deserialize(serialized, "").getOrThrow()
        (parsed.elementValue as ByteArray) shouldBe (item.elementValue as ByteArray)
    }

    "document serialization with ByteArray" {

        val elementId = uuid4().toString()
        val docType = "testByteDoc"


        val decodingFun: ItemValueDecoder =
            { descriptor: SerialDescriptor, index: Int, compositeDecoder: CompositeDecoder ->
                compositeDecoder.decodeSerializableElement(
                    descriptor,
                    index,
                    ByteArraySerializer()
                )
            }
        CborCredentialSerializer.register(
            mapOf(elementId to decodingFun),
            docType

        )
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = Random.nextBytes(32),
        )

        val doc = Document(
            docType,
            IssuerSigned(
                mapOf(
                    "noname" to IssuerSignedList(
                        listOf(ByteStringWrapper(item, item.serialize()))
                    )
                ), CoseSigned(ByteStringWrapper(CoseHeader(), CoseHeader().serialize()), null, null, byteArrayOf())
            ), DeviceSigned(Random.nextBytes(32), DeviceAuth())
        )

        val serialized = doc.serialize()

        serialized.encodeToString(Base16(true)).apply { println(this) }.shouldNotContain("D903EC")
        val parsed = Document.deserialize(serialized).getOrThrow()
        parsed shouldBe doc
    }

    "!serialization with LocalDate" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = LocalDate(2024, 1, 1)
        )

        val serialized = item.serialize()
        serialized.encodeToString(Base16(true)).shouldContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized, "").getOrThrow()
        parsed shouldBe item
    }

    "!serialization with Instant" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = Instant.parse("2021-01-01T00:00:00Z"),
        )

        val serialized = item.serialize()
        serialized.encodeToString(Base16(true)).shouldContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized, "").getOrThrow()
        parsed shouldBe item
    }

})
