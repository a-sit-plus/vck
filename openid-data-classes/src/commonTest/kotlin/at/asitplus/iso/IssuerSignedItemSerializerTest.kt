package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Instant

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
}
