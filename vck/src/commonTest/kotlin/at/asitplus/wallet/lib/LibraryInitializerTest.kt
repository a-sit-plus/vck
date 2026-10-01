package at.asitplus.wallet.lib

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.IssuerSignedListSerializer
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import com.benasher44.uuid.uuid4
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

private data class TestCredentialScheme(
    override val vcType: String? = null,
    override val sdJwtType: String? = null,
    override val isoNamespace: String? = null,
    override val isoDocType: String? = null,
    override val supportedRepresentations: Collection<CredentialRepresentation> = listOf(PLAIN_JWT),
) : CredentialScheme

val LibraryInitializerTest by matrixSuite {
    "serializer registration is safe when extension libraries initialize concurrently" {
        data class ConcurrentValue(val id: String)

        val prefix = uuid4().toString()
        coroutineScope {
            (0 until 1000).map { index ->
                launch(Dispatchers.Default) {
                    val id = "$prefix-$index"
                    JsonCredentialSerializer.register { value ->
                        (value as? ConcurrentValue)?.takeIf { it.id == id }?.let { JsonPrimitive(it.id) }
                    }
                }
            }.joinAll()
        }

        (0 until 1000).forEach { index ->
            val id = "$prefix-$index"
            JsonCredentialSerializer.encode(ConcurrentValue(id)) shouldBe JsonPrimitive(id)
        }
    }

    "registerExtensionLibrary registers schemes without serializer modules" {
        val scheme = TestCredentialScheme(
            vcType = "TestCredential-${uuid4()}",
        )

        LibraryInitializer.registerExtensionLibrary(scheme)

        AttributeIndex.resolveAttributeType(scheme.vcType!!) shouldBe scheme
    }

    "registerExtensionLibrary registers ISO encoders and serializers" {
        @Serializable
        data class MockIssuerSignedValue(val value: String)

        val elementId = "element-${uuid4()}"
        val isoNamespace = "namespace.${uuid4()}"

        LibraryInitializer.registerCredentialSerializers(
            jsonValueEncoder = { value: Any ->
                when (value) {
                    is MockIssuerSignedValue -> joseCompliantSerializer.encodeToJsonElement<MockIssuerSignedValue>(value)
                    else -> null
                }
            },
            itemValueSerializerMap = mapOf(
                isoNamespace to mapOf<String, KSerializer<MockIssuerSignedValue>>(
                    elementId to MockIssuerSignedValue.serializer()
                )
            ),
        )

        JsonCredentialSerializer.encode(MockIssuerSignedValue("encoded")) shouldBe
                joseCompliantSerializer.encodeToJsonElement(MockIssuerSignedValue("encoded"))

        val list = IssuerSignedList(
            listOf(
                ByteStringWrapper(
                    IssuerSignedItem(
                        digestId = 1u,
                        random = Random.nextBytes(16),
                        elementIdentifier = elementId,
                        elementValue = MockIssuerSignedValue("round-trip"),
                    )
                )
            )
        )
        val encodedList = coseCompliantSerializer.encodeToByteArray(
            IssuerSignedListSerializer(isoNamespace),
            list
        )
        val decodedList = coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedListSerializer(isoNamespace),
            encodedList
        )
        decodedList shouldBe list
    }
}
