package at.asitplus.wallet.lib.cbor

import at.asitplus.wallet.lib.iso.IssuerSignedItem
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.equals.shouldBeEqual
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Instant
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.random.nextUInt

class IssuerSignedItemSerializationTest : FreeSpec({

    "serialization with String" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = uuid4().toString(),
        )

        val serialized = item.serialize()
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized).getOrThrow()
        parsed shouldBe item
    }

    "serialization with ByteArray" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = Random.nextBytes(32),
        )

        val serialized = item.serialize()
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")
        val parsed = IssuerSignedItem.deserialize(serialized).getOrThrow()
        (parsed.elementValue as ByteArray) shouldBe (item.elementValue as ByteArray)
    }

    "serialization with LocalDate" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = LocalDate(2024, 1, 1)
        )

        val serialized = item.serialize()
         serialized.encodeToString(Base16(true)).shouldContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized).getOrThrow()
        parsed shouldBe item
    }

    "serialization with Instant" {
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = uuid4().toString(),
            elementValue = Instant.parse("2021-01-01T00:00:00Z"),
        )

        val serialized = item.serialize()
         serialized.encodeToString(Base16(true)).shouldContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized).getOrThrow()
        parsed shouldBe item
    }

})