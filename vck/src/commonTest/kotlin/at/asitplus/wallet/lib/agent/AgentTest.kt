@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

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

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(
            EphemeralKeyWithoutCert(),
            issuerCredentialStore,
            DummyCredentialDataProvider(),
        )
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
        verifier = VerifierAgent(holderKeyMaterial)
        challenge = uuid4().toString()
    }

    "simple walk-through success" {
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.keyMaterial.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val verified = verifier.verifyPresentation(vp.jws, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "wrong keyId in presentation leads to InvalidStructure" {
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )

        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = issuer.keyMaterial.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "revoked credentials must not be validated" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider().getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
        issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true

        val revocationListCredential =
            issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationListCredential.shouldNotBeNull()
        verifier.setRevocationList(revocationListCredential) shouldBe true

        verifier.verifyVcJws(credentials.vcJws)
            .shouldBeInstanceOf<Verifier.VerifyCredentialResult.Revoked>()
    }

    "building presentation with revoked credentials should not work" - {

        "when setting a revocation list before storing credentials" {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
            issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true
            val revocationListCredential =
                issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
            revocationListCredential.shouldNotBeNull()
            holder.setRevocationList(revocationListCredential) shouldBe true

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput())
            storedCredentials.isFailure shouldBe true
        }

        "and when setting a revocation list after storing credentials" {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            storedCredentials.shouldBeInstanceOf<Holder.StoredCredential.Vc>()

            issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true
            val revocationListCredential =
                issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
            revocationListCredential.shouldNotBeNull()
            holder.setRevocationList(revocationListCredential) shouldBe true

            holder.createPresentation(
                challenge = challenge,
                audienceId = verifier.keyMaterial.identifier,
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
                DummyCredentialDataProvider().getCredential(
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
                    it.status.shouldBe(Validator.RevocationStatus.UNKNOWN)
                }
            }

            "with a revocation list set" {
                holder.setRevocationList(
                    issuer.issueRevocationListCredential(
                        FixedTimePeriodProvider.timePeriod
                    )!!
                ) shouldBe true
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.filterIsInstance<Holder.StoredCredential.Vc>().forEach {
                    it.status.shouldBe(Validator.RevocationStatus.VALID)
                }
            }
        }

        "when the issuer has revoked them" {
            val credentials = issuer.issueCredential(
                DummyCredentialDataProvider().getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            storedCredentials.shouldBeInstanceOf<Holder.StoredCredential.Vc>()

            issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true
            val revocationListCredential =
                issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
            revocationListCredential.shouldNotBeNull()
            holder.setRevocationList(revocationListCredential) shouldBe true

            val holderCredentials = holder.getCredentials()
            holderCredentials.shouldNotBeNull()
            holderCredentials.filterIsInstance<Holder.StoredCredential.Vc>().forEach {
                it.status.shouldBe(Validator.RevocationStatus.REVOKED)
            }
        }
    }

    "building presentation without necessary credentials" {
        holder.createPresentation(
            challenge = challenge,
            audienceId = verifier.keyMaterial.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull() shouldBe null
    }

    "valid presentation is valid" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider().getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        holder.storeCredential(credentials.toStoreCredentialInput())
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifier.keyMaterial.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.revokedVerifiableCredentials.shouldBeEmpty()
        result.vp.verifiableCredentials shouldHaveSize 1
    }

    "valid presentation is valid -- some other attributes revoked" {
        val credentials = issuer.issueCredential(
            DummyCredentialDataProvider().getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        holder.storeCredential(credentials.toStoreCredentialInput())
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifier.keyMaterial.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()

        val credentialsToRevoke = issuer.issueCredential(
            DummyCredentialDataProvider().getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow()
        ).getOrThrow()
        credentialsToRevoke.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
        issuer.revokeCredentials(listOf(credentialsToRevoke.vcJws)) shouldBe true
        val revocationList =
            issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()
        verifier.setRevocationList(revocationList) shouldBe true

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

})
