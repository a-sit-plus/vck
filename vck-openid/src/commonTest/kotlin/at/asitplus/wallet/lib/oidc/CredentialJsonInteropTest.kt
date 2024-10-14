package at.asitplus.wallet.lib.oidc

import at.asitplus.jsonpath.JsonPath
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

class CredentialJsonInteropTest : FreeSpec({

    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var issuerAgent: Issuer
    lateinit var subjectCredentialStore: SubjectCredentialStore
    lateinit var holderAgent: Holder

    beforeEach {
        holderKeyMaterial = EphemeralKeyWithoutCert()
        subjectCredentialStore = InMemorySubjectCredentialStore()
        holderAgent = HolderAgent(holderKeyMaterial, subjectCredentialStore)
        issuerAgent = IssuerAgent(EphemeralKeyWithSelfSignedCert())
    }

    "Plain jwt credential path resolving" {
        holderAgent.storeCredential(
            issuerAgent.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
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
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.SD_JWT,
                    ConstantIndex.AtomicAttribute2023.claimNames
                ).getOrThrow(),
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
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    ConstantIndex.AtomicAttribute2023.claimNames
                ).getOrThrow()
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
