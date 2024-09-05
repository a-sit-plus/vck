package at.asitplus.wallet.lib.cbor

import at.asitplus.signum.indispensable.cosef.CoseHeader
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.iso.*
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotContain
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
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

        val serialized = item.serialize("foobar")
        serialized.encodeToString(Base16(true)).shouldNotContain("D903EC")

        val parsed = IssuerSignedItem.deserialize(serialized, "").getOrThrow()
        parsed shouldBe item
    }

    "document serialization with ByteArray" {

        val elementId = uuid4().toString()
        val namespace = "testNS"


        CborCredentialSerializer.register(
            mapOf(elementId to ByteArraySerializer()),
            namespace

        )
        val item = IssuerSignedItem(
            digestId = Random.nextUInt(),
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = Random.nextBytes(32),
        )

        val doc = Document(
            "dummyDoc",
            IssuerSigned(
                mapOf(
                    namespace to listOf(item)
                ), CoseSigned(ByteStringWrapper(CoseHeader(), CoseHeader().serialize()), null, null, byteArrayOf())
            ), DeviceSigned(Random.nextBytes(32), DeviceAuth())
        )

        val serialized = doc.serialize()

        serialized.encodeToString(Base16(true)).apply { println(this) }.shouldNotContain("D903EC")
        val parsed = Document.deserialize(serialized).getOrThrow()
        parsed shouldBe doc
    }

})
