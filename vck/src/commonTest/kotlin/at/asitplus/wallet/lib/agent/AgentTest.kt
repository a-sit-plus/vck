@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlin.random.Random


class AgentTest : FreeSpec({
    val singularPresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = listOf(DifInputDescriptor(id = uuid4().toString()))
    )

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var challenge: String
    lateinit var validator: Validator
    lateinit var verifierId: String

    beforeEach {
        validator = Validator(
            resolveStatusListToken = {
                if (Random.nextBoolean()) StatusListToken.StatusListJwt(
                    issuer.issueStatusListJwt(),
                    resolvedAt = Clock.System.now()
                ) else {
                    StatusListToken.StatusListCwt(
                        issuer.issueStatusListCwt(),
                        resolvedAt = Clock.System.now()
                    )
                }
            },
        )

        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()

        issuer = IssuerAgent(
            EphemeralKeyWithoutCert(),
            issuerCredentialStore,
            validator = validator,
        )

        holderKeyMaterial = EphemeralKeyWithoutCert()
        verifierId = "urn:${uuid4()}"
        holder = HolderAgent(
            holderKeyMaterial, holderCredentialStore,
            validator = validator,
        )
        verifier = VerifierAgent(
            identifier = verifierId,
            validator = validator,
        )
        challenge = uuid4().toString()
    }

    "simple walk-through success" {
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

        holder.getCredentials()?.size shouldBe 1

        val presentationParameters = holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
            presentationDefinition = singularPresentationDefinition,
        ).getOrThrow()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<CreatePresentationResult.Signed>()
        val verified = verifier.verifyPresentation(vp.jws, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "wrong keyId in presentation leads to InvalidStructure" {
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()

        val presentationParameters = holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = issuer.keyMaterial.identifier),
            presentationDefinition = singularPresentationDefinition,
        ).getOrThrow()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "revoked credentials must not be validated" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
        issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true

        validator.verifyVcJws(credentials.vcJws, holderKeyMaterial.publicKey)
            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.Revoked>()
    }

    "building presentation with revoked credentials should not work" - {

        "when setting a revocation list before storing credentials" {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
            issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput())
            storedCredentials.isFailure shouldBe true
        }

        "and when setting a revocation list after storing credentials" {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            storedCredentials.shouldBeInstanceOf<Holder.StoredCredential.Vc>()

            issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true

            holder.createPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = "urn:${uuid4()}"),
                presentationDefinition = singularPresentationDefinition,
            ).getOrNull() shouldBe null
        }
    }

    "getting credentials that have been stored by the holder" - {

        "when there are no credentials stored" {
            val holderCredentials = holder.getCredentials()
            holderCredentials.shouldNotBeNull()
            holderCredentials.shouldBeEmpty()
        }

        "when they are valid" - {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            storedCredentials.shouldBeInstanceOf<Holder.StoredCredential.Vc>()

            "without a revocation list set" {
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.filterIsInstance<Holder.StoredCredential.Vc>().forEach {
                    it.status.shouldBe(null)
                }
            }

            "with a revocation list set" {
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.filterIsInstance<Holder.StoredCredential.Vc>().forEach {
                    it.status.shouldBe(TokenStatus.Valid)
                }
            }
        }

        "when the issuer has revoked them" {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            storedCredentials.shouldBeInstanceOf<Holder.StoredCredential.Vc>()

            issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true

            val holderCredentials = holder.getCredentials()
            holderCredentials.shouldNotBeNull()
            holderCredentials.filterIsInstance<Holder.StoredCredential.Vc>().forEach {
                it.status.shouldBe(TokenStatus.Invalid)
            }
        }
    }

    "building presentation without necessary credentials" {
        holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = "urn:${uuid4()}"),
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull() shouldBe null
    }

    "valid presentation is valid" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
        val presentationParameters = holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<CreatePresentationResult.Signed>()

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.revokedVerifiableCredentials.shouldBeEmpty()
        result.vp.verifiableCredentials shouldHaveSize 1
    }

    "valid presentation is valid -- some other attributes revoked" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
        val presentationParameters = holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<CreatePresentationResult.Signed>()

        val credentialsToRevoke = issuer.issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        credentialsToRevoke.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
        issuer.revokeCredentials(listOf(credentialsToRevoke.vcJws)) shouldBe true

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

})
