package at.asitplus.wallet.lib

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedList
import at.asitplus.iso.IssuerSignedListSerializer
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

private data class TestCredentialScheme(
    override val schemaUri: String,
    override val vcType: String? = null,
    override val sdJwtType: String? = null,
    override val isoNamespace: String? = null,
    override val isoDocType: String? = null,
    override val claimNames: Collection<String> = emptyList(),
    override val supportedRepresentations: Collection<ConstantIndex.CredentialRepresentation> = listOf(
        ConstantIndex.CredentialRepresentation.PLAIN_JWT
    ),
) : ConstantIndex.CredentialScheme

@Suppress("DEPRECATION")
val LibraryInitializerTest by testSuite {
    "registerExtensionLibrary registers schemes without serializer modules" {
        val scheme = TestCredentialScheme(
            schemaUri = "urn:test:${uuid4()}",
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
        val scheme = TestCredentialScheme(
            schemaUri = "urn:test:${uuid4()}",
            vcType = "IsoCredential-${uuid4()}",
            isoNamespace = isoNamespace,
            isoDocType = "doctype.${uuid4()}",
            supportedRepresentations = listOf(ConstantIndex.CredentialRepresentation.ISO_MDOC),
        )

        val jsonValueEncoder: JsonValueEncoder = { value ->
            when (value) {
                is MockIssuerSignedValue -> joseCompliantSerializer.encodeToJsonElement(value)
                else -> null
            }
        }
        val itemValueSerializerMap = mapOf(
            elementId to MockIssuerSignedValue.serializer()
        )

        LibraryInitializer.registerExtensionLibrary(
            scheme,
            jsonValueEncoder = jsonValueEncoder,
            itemValueSerializerMap = itemValueSerializerMap,
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
