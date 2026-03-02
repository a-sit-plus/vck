package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Instant
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromByteArray
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborObject
import net.orandja.obor.data.CborText

@Serializable
private data class ItemNestedElementValue(val value: Int)

val IssuerSignedItemSerializerTest by testSuite {
    "deserializes instant elementValue even when elementIdentifier is provided afterwards" {
        val namespace = "test.namespace"
        val elementIdentifier = "timestamp"
        CborCredentialSerializer.register(mapOf(elementIdentifier to InstantStringSerializer), namespace)

        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = Clock.System.now(),
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(
            IssuerSignedItemSerializer(namespace, elementIdentifier),
            item
        )

        coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedItemSerializer(namespace, ""),
            serialized,
        ) shouldBe item
    }

    "uses obor container and decodes complex elementValue when elementIdentifier comes later" {
        val namespace = "test.namespace"
        val elementIdentifier = "nested"
        CborCredentialSerializer.register(mapOf(elementIdentifier to ItemNestedElementValue.serializer()), namespace)

        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = ItemNestedElementValue(42),
        )

        val serialized = coseCompliantSerializer.encodeToByteArray(
            IssuerSignedItemSerializer(namespace, elementIdentifier),
            item,
        )
        val parsed = Cbor.decodeFromByteArray<CborObject>(serialized) as CborMap
        val reordered = CborMap(
            parsed.elements.sortedBy {
                when ((it.key as CborText).value) {
                    IssuerSignedItem.PROP_ELEMENT_VALUE -> 0
                    IssuerSignedItem.PROP_ELEMENT_ID -> 1
                    else -> 2
                }
            }.toMutableList(),
            parsed.indefinite
        )

        IssuerSignedItemSerializer(namespace, "").deserializeFromOborMap(reordered) shouldBe item
    }
}
