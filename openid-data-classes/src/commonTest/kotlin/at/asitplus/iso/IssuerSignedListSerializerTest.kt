package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlin.random.Random
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encodeToHexString
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborBoolean
import net.orandja.obor.data.CborBytes
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborObject
import net.orandja.obor.data.CborPositive
import net.orandja.obor.data.CborText
import kotlin.random.nextULong
import kotlin.time.Clock

val IssuerSignedListSerializerTest by testSuite {

    "deserializes elementValue from generic obor container once elementIdentifier is known" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()

        CborCredentialSerializer.register(
            mapOf(elementIdentifier to ListNestedElementValue.serializer()), namespace
        )

        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = ListNestedElementValue(Random.nextInt()),
        )

        val list = IssuerSignedList(listOf(ByteStringWrapper(item)))
        val serialized = coseCompliantSerializer.encodeToByteArray(IssuerSignedListSerializer(namespace), list)
        coseCompliantSerializer.decodeFromByteArray(IssuerSignedListSerializer(namespace), serialized) shouldBe list
    }

    "deserializes any elementValue even when no custom deserializer is given" - {
        withData(
            nameFn = { it::class.simpleName ?: it.toString() },
            listOf(
                Clock.System.now(),
                Random.nextLong(),
                uuid4().toString(),
                // needs custom registered deserializer, see below Random.nextBoolean(),
                // needs custom registered deserializer, see below Random.nextInt(),
                // needs custom registered deserializer, see below Random.nextBytes(16),
            )
        ) {
            val namespace = uuid4().toString()
            val elementIdentifier = uuid4().toString()

            val item = IssuerSignedItem(
                digestId = 1u,
                random = Random.nextBytes(16),
                elementIdentifier = elementIdentifier,
                elementValue = it
            )

            val list = IssuerSignedList(listOf(ByteStringWrapper(item)))
            val serialized = coseCompliantSerializer.encodeToByteArray(IssuerSignedListSerializer(namespace), list)
            coseCompliantSerializer.decodeFromByteArray(IssuerSignedListSerializer(namespace), serialized) shouldBe list
        }
    }

    "deserializes IssuerSignedItem with elementValue being a nested object before elementIdentifier" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()

        CborCredentialSerializer.register(
            mapOf(elementIdentifier to ListNestedElementValue.serializer()), namespace
        )
        val elementValue = ListNestedElementValue(7)
        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = elementValue,
        )

        val reordered = CborObject.orderedMap(
            CborText(IssuerSignedItem.PROP_DIGEST_ID) to CborObject.positive(item.digestId),
            CborText(IssuerSignedItem.PROP_RANDOM) to CborObject.value(item.random),
            CborText(IssuerSignedItem.PROP_ELEMENT_VALUE) to elementValue.toOborObject(),
            CborText(IssuerSignedItem.PROP_ELEMENT_ID) to CborText(item.elementIdentifier),
        )

        assertRoundtrip(item, namespace, reordered)
    }

    "deserializes IssuerSignedItem with elementValue being a boolean before elementIdentifier" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()

        CborCredentialSerializer.register(
            mapOf(elementIdentifier to Boolean.serializer()), namespace
        )
        val elementValue = Random.nextBoolean()
        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = elementValue,
        )

        val reordered = CborObject.orderedMap(
            CborText(IssuerSignedItem.PROP_DIGEST_ID) to CborObject.positive(item.digestId),
            CborText(IssuerSignedItem.PROP_RANDOM) to CborObject.value(item.random),
            CborText(IssuerSignedItem.PROP_ELEMENT_VALUE) to CborBoolean(elementValue),
            CborText(IssuerSignedItem.PROP_ELEMENT_ID) to CborText(item.elementIdentifier),
        )

        assertRoundtrip(item, namespace, reordered)
    }

    "deserializes IssuerSignedItem with elementValue being a ULong before elementIdentifier" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()

        CborCredentialSerializer.register(
            mapOf(elementIdentifier to ULong.serializer()), namespace
        )
        val elementValue = Random.nextULong()
        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = elementValue,
        )

        val reordered = CborObject.orderedMap(
            CborText(IssuerSignedItem.PROP_DIGEST_ID) to CborObject.positive(item.digestId),
            CborText(IssuerSignedItem.PROP_RANDOM) to CborObject.value(item.random),
            CborText(IssuerSignedItem.PROP_ELEMENT_VALUE) to CborPositive(elementValue),
            CborText(IssuerSignedItem.PROP_ELEMENT_ID) to CborText(item.elementIdentifier),
        )

        assertRoundtrip(item, namespace, reordered)
    }

    "deserializes IssuerSignedItem with elementValue being a ByteArray before elementIdentifier" {
        val namespace = uuid4().toString()
        val elementIdentifier = uuid4().toString()

        CborCredentialSerializer.register(
            mapOf(elementIdentifier to ByteArraySerializer()), namespace
        )
        val elementValue = Random.nextBytes(16)
        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = elementValue,
        )

        val reordered = CborObject.orderedMap(
            CborText(IssuerSignedItem.PROP_DIGEST_ID) to CborObject.positive(item.digestId),
            CborText(IssuerSignedItem.PROP_RANDOM) to CborObject.value(item.random),
            CborText(IssuerSignedItem.PROP_ELEMENT_VALUE) to CborBytes(elementValue),
            CborText(IssuerSignedItem.PROP_ELEMENT_ID) to CborText(item.elementIdentifier),
        )

        assertRoundtrip(item, namespace, reordered)
    }
}

private fun assertRoundtrip(
    item: IssuerSignedItem,
    namespace: String,
    reordered: CborMap
) {
    val list = IssuerSignedList(listOf(ByteStringWrapper(item)))
    val serialized = coseCompliantSerializer.encodeToHexString(IssuerSignedListSerializer(namespace), list)

    val serializedReordered = reordered.wrapInIssuerSignedItemListSerialized()
    serializedReordered shouldNotBe serialized

    coseCompliantSerializer.decodeFromHexString(IssuerSignedListSerializer(namespace), serialized) shouldBe list
    coseCompliantSerializer.decodeFromHexString(
        IssuerSignedListSerializer(namespace),
        serializedReordered
    ) shouldBe list
}

private fun CborMap.wrapInIssuerSignedItemListSerialized(): String = "81" + // array(1)
        "d818" +  // encoded cbor data item, tagged(24)
        Cbor.encodeToHexString(CborBytes(Cbor.encodeToByteArray<CborMap>(this)))

private fun ListNestedElementValue.toOborObject(): CborObject = Cbor.decodeFromByteArray<CborObject>(
    coseCompliantSerializer.encodeToByteArray<ListNestedElementValue>(this)
)

@Serializable
private data class ListNestedElementValue(val value: Int)
