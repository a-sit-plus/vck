package at.asitplus.wallet.lib.openid

import at.asitplus.jsonpath.JsonPath
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.InMemorySubjectCredentialStore
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.rfc3986.toUri
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

val CredentialJsonInteropTest by testSuite {
    withFixtureGenerator {
        object {
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val subjectCredentialStore = InMemorySubjectCredentialStore()
            val holderAgent = HolderAgent(holderKeyMaterial, subjectCredentialStore)
            val issuerAgent = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
        }
    } - {
        test("Plain jwt credential path resolving") {
            it.holderAgent.storeCredential(
                it.issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        AtomicAttribute2023,
                        PLAIN_JWT
                    ).getOrThrow(),
                ).getOrThrow().toStoreCredentialInput()
            )

            val credential =
                CredentialToJsonConverter.toJsonElement(it.subjectCredentialStore.getCredentials().getOrThrow()[0])
            credential.getByJsonPath("\$.id").content shouldNotBe null
            credential.getByJsonPath("\$['id']").content shouldNotBe null
            credential.getByJsonPath("\$.name").content shouldNotBe null
            credential.getByJsonPath("\$['name']").content shouldNotBe null
            credential.getByJsonPath("\$['mime-type']").content shouldNotBe null
            credential.getByJsonPath("\$.value").content shouldNotBe null
            credential.getByJsonPath("\$['value']").content shouldNotBe null
        }

        test("SD jwt credential path resolving") {
            it.holderAgent.storeCredential(
                it.issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        AtomicAttribute2023,
                        SD_JWT,
                    ).getOrThrow(),
                ).getOrThrow().toStoreCredentialInput()
            )

            val credential =
                CredentialToJsonConverter.toJsonElement(it.subjectCredentialStore.getCredentials().getOrThrow()[0])
            credential.getByJsonPath("\$['${AtomicAttribute2023.CLAIM_GIVEN_NAME}']").content shouldNotBe null
            credential.getByJsonPath("\$['${AtomicAttribute2023.CLAIM_FAMILY_NAME}']").content shouldNotBe null
            credential.getByJsonPath("\$['${AtomicAttribute2023.CLAIM_DATE_OF_BIRTH}']").content shouldNotBe null
        }

        test("ISO credential path resolving") {
            it.holderAgent.storeCredential(
                it.issuerAgent.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        AtomicAttribute2023,
                        ISO_MDOC,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            )

            val credential =
                CredentialToJsonConverter.toJsonElement(it.subjectCredentialStore.getCredentials().getOrThrow()[0])
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
    }
}

private fun JsonElement.getByJsonPath(path: String) =
    (JsonPath(path).query(this).first().value as JsonPrimitive)
