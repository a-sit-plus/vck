package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.JsonPath
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyWithCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
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

    lateinit var holderKeyPair: KeyWithCert

    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder

    beforeEach {
        holderKeyPair = EphemeralKeyWithSelfSignedCert()
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent(holderKeyPair, subjectCredentialStore)
        issuerAgent = IssuerAgent(EphemeralKeyWithSelfSignedCert(), DummyCredentialDataProvider())
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
                ConstantIndex.AtomicAttribute2023.claimNames
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['given_name']").content shouldNotBe null
        credential.getByJsonPath("\$['family_name']").content shouldNotBe null
        credential.getByJsonPath("\$['date_of_birth']").content shouldNotBe null
    }

    "ISO credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.ISO_MDOC,
                ConstantIndex.AtomicAttribute2023.claimNames
            ).getOrThrow().toStoreCredentialInput()
        )

        val credential =
            CredentialToJsonConverter.toJsonElement(subjectCredentialStore.getCredentials().getOrThrow()[0])
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['given_name']").content shouldNotBe null
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['family_name']").content shouldNotBe null
        credential.getByJsonPath("\$['${ConstantIndex.AtomicAttribute2023.isoNamespace}']['date_of_birth']").content shouldNotBe null
    }
})

private fun JsonElement.getByJsonPath(path: String) =
    (JsonPath(path).query(this).first().value as JsonPrimitive)
