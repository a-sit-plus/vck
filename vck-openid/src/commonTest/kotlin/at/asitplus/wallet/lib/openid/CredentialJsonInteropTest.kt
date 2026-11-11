package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
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
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStorePlainJwt
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

val CredentialJsonInteropTest by matrixSuite {
    fixture {
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
            issueAndStorePlainJwt(it.holderAgent, it.holderKeyMaterial, it.issuerAgent)

            val credential =
                CredentialToJsonConverter.toJsonElement(it.subjectCredentialStore.getCredentials().getOrThrow()[0])
            listOf("id", "name", "mime-type", "value").forEach { claimName ->
                credential.shouldHavePrimitiveAt(DCQLClaimsPathPointer(claimName))
            }
        }

        test("SD jwt credential path resolving") {
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, it.issuerAgent)

            val credential =
                CredentialToJsonConverter.toJsonElement(it.subjectCredentialStore.getCredentials().getOrThrow()[0])
            listOf(
                AtomicAttribute2023.CLAIM_GIVEN_NAME,
                AtomicAttribute2023.CLAIM_FAMILY_NAME,
                AtomicAttribute2023.CLAIM_DATE_OF_BIRTH,
            ).forEach { claimName ->
                credential.shouldHavePrimitiveAt(DCQLClaimsPathPointer(claimName))
            }
        }

        test("ISO credential path resolving") {
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, it.issuerAgent)

            val credential =
                CredentialToJsonConverter.toJsonElement(it.subjectCredentialStore.getCredentials().getOrThrow()[0])
            // ISO/IEC 18013-5 has no paths: the view maps each name space to its data elements
            val namespace = credential.jsonObject[AtomicAttribute2023.isoNamespace].shouldNotBeNull().jsonObject
            listOf(
                AtomicAttribute2023.CLAIM_GIVEN_NAME,
                AtomicAttribute2023.CLAIM_FAMILY_NAME,
                AtomicAttribute2023.CLAIM_DATE_OF_BIRTH,
            ).forEach { claimName ->
                namespace[claimName].shouldNotBeNull()
            }
        }
    }
}

/** The claim [pointer] selects is present once, as a primitive value (OpenID4VP 1.0, 7.1). */
private fun JsonElement.shouldHavePrimitiveAt(pointer: DCQLClaimsPathPointer) =
    pointer.query(this).single().value.shouldBeInstanceOf<JsonPrimitive>()
