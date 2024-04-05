package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.agent.toJsonElement
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.matchJsonPath
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonPrimitive

class CredentialJsonInteropTest : FreeSpec({

    lateinit var relyingPartyUrl: String
    lateinit var walletUrl: String

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService

    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder
    lateinit var verifierAgent: Verifier

    lateinit var holderSiop: OidcSiopWallet
    lateinit var verifierSiop: OidcSiopVerifier

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        relyingPartyUrl = "https://example.com/rp/${uuid4()}"
        walletUrl = "https://example.com/wallet/${uuid4()}"
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent.newDefaultInstance(holderCryptoService, subjectCredentialStore = subjectCredentialStore)
        verifierAgent = VerifierAgent.newDefaultInstance(verifierCryptoService.publicKey.didEncoded)
        issuerAgent = IssuerAgent.newDefaultInstance(
            DefaultCryptoService(),
            dataProvider = DummyCredentialDataProvider(),
        )

        holderSiop = OidcSiopWallet.newInstance(
            holder = holderAgent,
            cryptoService = holderCryptoService
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

        val credential = subjectCredentialStore.getCredentials().getOrThrow()[0]
        println(credential)

        (credential.toJsonElement().matchJsonPath("\$.id").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$.name").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$.mime-type").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$.value").entries.first().value as JsonPrimitive).content shouldNotBe null
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

        val credential = subjectCredentialStore.getCredentials().getOrThrow()[0]
        println(credential)

        (credential.toJsonElement().matchJsonPath("\$.id").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$.name").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$.mime-type").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$.value").entries.first().value as JsonPrimitive).content shouldNotBe null
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

        val credential = subjectCredentialStore.getCredentials().getOrThrow()[0]
        println(credential)

        (credential.toJsonElement().matchJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].id").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].name").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].mime-type").entries.first().value as JsonPrimitive).content shouldNotBe null
        (credential.toJsonElement().matchJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}'].value").entries.first().value as JsonPrimitive).content shouldNotBe null
    }
})
