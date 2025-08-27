package at.asitplus.wallet.lib.openid

import at.asitplus.jsonpath.JsonPath
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

class CredentialJsonInteropTest : FreeSpec({
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent(holderKeyMaterial, subjectCredentialStore)
        issuerAgent = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
    }

    "Plain jwt credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    AtomicAttribute2023,
                    PLAIN_JWT
                ).getOrThrow(),
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$.id").content shouldNotBe null
        credential.getByJsonPath("\$['id']").content shouldNotBe null
        credential.getByJsonPath("\$.name").content shouldNotBe null
        credential.getByJsonPath("\$['name']").content shouldNotBe null
        credential.getByJsonPath("\$['mime-type']").content shouldNotBe null
        credential.getByJsonPath("\$.value").content shouldNotBe null
        credential.getByJsonPath("\$['value']").content shouldNotBe null
    }

    "SD jwt credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    AtomicAttribute2023,
                    SD_JWT,
                ).getOrThrow(),
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['${AtomicAttribute2023.CLAIM_GIVEN_NAME}']").content shouldNotBe null
        credential.getByJsonPath("\$['${AtomicAttribute2023.CLAIM_FAMILY_NAME}']").content shouldNotBe null
        credential.getByJsonPath("\$['${AtomicAttribute2023.CLAIM_DATE_OF_BIRTH}']").content shouldNotBe null
    }

    "ISO credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    AtomicAttribute2023,
                    ISO_MDOC,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['${AtomicAttribute2023.isoNamespace}']['${AtomicAttribute2023.CLAIM_GIVEN_NAME}']").content shouldNotBe null
        credential.getByJsonPath("\$['${AtomicAttribute2023.isoNamespace}']['${AtomicAttribute2023.CLAIM_FAMILY_NAME}']").content shouldNotBe null
        credential.getByJsonPath("\$['${AtomicAttribute2023.isoNamespace}']['${AtomicAttribute2023.CLAIM_DATE_OF_BIRTH}']").content shouldNotBe null
    }

    "Simple JSONPaths" {
        val randomValue = uuid4().toString()
        val input = buildJsonObject {
            put("address", buildJsonObject {
                put("formatted", JsonPrimitive(randomValue))
            })
        }
        input.getByJsonPath("$.address.formatted").content shouldBe randomValue
        input.getByJsonPath("$[\"address\"][\"formatted\"]").content shouldBe randomValue
        input.getByJsonPath("$.address[\"formatted\"]").content shouldBe randomValue
        JsonPath("$.address").query(input).apply { size shouldBe 1 }
        shouldThrow<Throwable> {
            JsonPath("$.address.[\"formatted\"]")
        }
    }
})

private fun JsonElement.getByJsonPath(path: String) =
    (JsonPath(path).query(this).first().value as JsonPrimitive)
