package at.asitplus.wallet.lib

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.IssuerSignedItemSerializer
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.testballoon.invoke
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.data.JsonCredentialSerializer
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
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

val LibraryInitializerTest by testSuite {
    "registerExtensionLibrary registers schemes and serializers" {
        @Serializable
        @SerialName("TestCredentialSubject")
        data class TestCredentialSubject(
            override val id: String,
            val subjectName: String,
        ) : CredentialSubject()

        val scheme = TestCredentialScheme(
            schemaUri = "urn:test:${uuid4()}",
            vcType = "TestCredential-${uuid4()}",
        )
        val serializersModule = SerializersModule {
            polymorphic(CredentialSubject::class) {
                subclass(TestCredentialSubject::class)
            }
        }

        LibraryInitializer.registerExtensionLibrary(scheme, serializersModule)

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
                is MockIssuerSignedValue -> vckJsonSerializer.encodeToJsonElement(value)
                else -> null
            }
        }
        val itemValueSerializerMap = mapOf(
            elementId to MockIssuerSignedValue.serializer()
        )

        LibraryInitializer.registerExtensionLibrary(
            scheme,
            serializersModule = null,
            jsonValueEncoder = jsonValueEncoder,
            itemValueSerializerMap = itemValueSerializerMap,
        )

        JsonCredentialSerializer.encode(MockIssuerSignedValue("encoded")) shouldBe
            vckJsonSerializer.encodeToJsonElement(MockIssuerSignedValue("encoded"))

        val item = IssuerSignedItem(
            digestId = 1u,
            random = Random.nextBytes(16),
            elementIdentifier = elementId,
            elementValue = MockIssuerSignedValue("round-trip"),
        )
        val encodedItem =
            coseCompliantSerializer.encodeToByteArray(IssuerSignedItemSerializer(isoNamespace, elementId), item)
        val decodedItem = coseCompliantSerializer.decodeFromByteArray(
            IssuerSignedItemSerializer(isoNamespace, elementId),
            encodedItem
        )

        decodedItem shouldBe item
    }
}
