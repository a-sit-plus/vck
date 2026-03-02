package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.random.Random
import kotlinx.serialization.Serializable

@Serializable
private data class NestedElementValue(val value: Int)

val IssuerSignedListSerializerTest by testSuite {
    "deserializes elementValue from generic obor container once elementIdentifier is known" {
        val namespace = "test.namespace"
        val elementIdentifier = "nested"
        CborCredentialSerializer.register(mapOf(elementIdentifier to NestedElementValue.serializer()), namespace)

        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementIdentifier,
            elementValue = NestedElementValue(7),
        )
        val list = IssuerSignedList(listOf(ByteStringWrapper(item)))

        val serialized = coseCompliantSerializer.encodeToByteArray(IssuerSignedListSerializer(namespace), list)

        coseCompliantSerializer.decodeFromByteArray(IssuerSignedListSerializer(namespace), serialized) shouldBe list
    }
}
