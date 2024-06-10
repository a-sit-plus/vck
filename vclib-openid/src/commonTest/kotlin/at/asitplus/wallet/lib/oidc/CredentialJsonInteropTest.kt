package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.JsonPath
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomKeyPairAdapter
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

@Suppress("unused")
class CredentialJsonInteropTest : FreeSpec({

    lateinit var holderCryptoService: CryptoService

    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder

    beforeEach {
        holderCryptoService = DefaultCryptoService(RandomKeyPairAdapter())
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent(holderCryptoService, subjectCredentialStore)
        issuerAgent = IssuerAgent(DefaultCryptoService(RandomKeyPairAdapter()), DummyCredentialDataProvider())
    }

    "Plain jwt credential path resolving" {
        runBlocking {
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.keyPairAdapter.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).toStoreCredentialInput()
            )
        }

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
        runBlocking {
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.keyPairAdapter.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    claimNames = listOf("given-name", "family-name", "date-of-birth", "is-active"),
                ).toStoreCredentialInput()
            )
        }

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['given-name']").content shouldNotBe null
        credential.getByJsonPath("\$['family-name']").content shouldNotBe null
        credential.getByJsonPath("\$['date-of-birth']").content shouldNotBe null
        credential.getByJsonPath("\$['is-active']").content shouldNotBe null
    }

    "ISO credential path resolving" {
        runBlocking {
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.keyPairAdapter.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    claimNames = listOf("given-name", "family-name", "date-of-birth", "is-active"),
                ).toStoreCredentialInput()
            )
        }

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
