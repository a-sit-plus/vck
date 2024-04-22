@file:Suppress("unused")

package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toJsonElement
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.jsonPath.JsonPath
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive

class CredentialJsonInteropTest : FreeSpec({

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService, subjectCredentialStore = subjectCredentialStore)
        issuerAgent = IssuerAgent.newDefaultInstance(
            DefaultCryptoService(),
            dataProvider = DummyCredentialDataProvider(),
        )
    }

    "Plain jwt credential path resolving" {
        runBlocking {
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).toStoreCredentialInput()
            )
        }

        val credential = subjectCredentialStore.getCredentials().getOrThrow()[0].toJsonElement()
        (JsonPath("\$.id").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['id']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$.name").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['name']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['mime-type']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$.value").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['value']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
    }

    "SD jwt credential path resolving" {
        runBlocking {
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.SD_JWT,
                    claimNames = listOf("id", "name", "mime-type", "value"),
                ).toStoreCredentialInput()
            )
        }

        val credential = subjectCredentialStore.getCredentials().getOrThrow()[0].toJsonElement()
        (JsonPath("\$.id").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['id']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$.name").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['name']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['mime-type']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$.value").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['value']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
    }

    "ISO credential path resolving" {
        runBlocking {
            holderAgent.storeCredentials(
                issuerAgent.issueCredential(
                    subjectPublicKey = holderCryptoService.publicKey,
                    attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    claimNames = listOf("id", "name", "mime-type", "value"),
                ).toStoreCredentialInput()
            )
        }

        val credential = subjectCredentialStore.getCredentials().getOrThrow()[0].toJsonElement()
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].id").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['id']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].name").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['name']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['mime-type']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].value").query(credential).first().value as JsonPrimitive).content shouldNotBe null
        (JsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['value']").query(credential).first().value as JsonPrimitive).content shouldNotBe null
    }
})
