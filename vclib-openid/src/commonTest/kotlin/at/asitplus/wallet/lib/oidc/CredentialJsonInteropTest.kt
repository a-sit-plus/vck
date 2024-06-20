package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.JsonPath
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyPairAdapter
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

@Suppress("unused")
class CredentialJsonInteropTest : FreeSpec({

    lateinit var holderKeyPair: KeyPairAdapter

    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder

    beforeEach {
        holderKeyPair = RandomKeyPairAdapter()
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent(holderKeyPair, subjectCredentialStore)
        issuerAgent = IssuerAgent(RandomKeyPairAdapter(), DummyCredentialDataProvider())
    }

    "Plain jwt credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
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
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
                listOf("given-name", "family-name", "date-of-birth", "is-active"),
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['given-name']").content shouldNotBe null
        credential.getByJsonPath("\$['family-name']").content shouldNotBe null
        credential.getByJsonPath("\$['date-of-birth']").content shouldNotBe null
        credential.getByJsonPath("\$['is-active']").content shouldNotBe null
    }

    "ISO credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
                listOf("given-name", "family-name", "date-of-birth", "is-active"),
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['given-name']").content shouldNotBe null
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['family-name']").content shouldNotBe null
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['date-of-birth']").content shouldNotBe null
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['is-active']").content shouldNotBe null
    }
})

private fun JsonElement.getByJsonPath(path: String) =
    (JsonPath(path).query(this).first().value as JsonPrimitive)
