@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class ValidatorVpTest : FreeSpec({
    val singularPresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = listOf(DifInputDescriptor(id = uuid4().toString()))
    )

    lateinit var validator: Validator
    lateinit var issuer: Issuer
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holder: HolderAgent
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderJwsService: JwsService
    lateinit var holderKeyPair: KeyPairAdapter
    lateinit var verifier: Verifier
    lateinit var challenge: String

    beforeEach {
        validator = Validator()
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent(
            EphemeralKeyPariAdapter(),
            issuerCredentialStore,
            DummyCredentialDataProvider(),
        )
        holderCredentialStore = InMemorySubjectCredentialStore()
        holderKeyPair = EphemeralKeyPariAdapter()
        holder = HolderAgent(holderKeyPair, holderCredentialStore)
        holderJwsService = DefaultJwsService(DefaultCryptoService(holderKeyPair, PlatformCryptoShim(holderKeyPair)))
        verifier = VerifierAgent()
        challenge = uuid4().toString()

        holder.storeCredential(
            issuer.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )
    }

    "correct challenge in VP leads to Success" {
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifier.keyPair.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "wrong structure of VC is detected" {
        val holderCredentials = holder.getCredentials()
        holderCredentials.shouldNotBeNull()
        val holderVcSerialized = holderCredentials
            .filterIsInstance<Holder.StoredCredential.Vc>()
            .map { it.storeEntry.vcSerialized }
            .map { it.reversed() }
        val vp = holder.createVcPresentation(holderVcSerialized, challenge, verifier.keyPair.identifier).getOrNull()
        vp.shouldNotBeNull()

        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.verifiableCredentials.shouldBeEmpty()
        result.vp.revokedVerifiableCredentials.shouldBeEmpty()
        result.vp.invalidVerifiableCredentials.shouldBe(holderVcSerialized)
    }

    "wrong challenge in VP leads to InvalidStructure" {
        val presentationParameters = holder.createPresentation(
            challenge = "challenge",
            audienceId = verifier.keyPair.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "wrong audience in VP leads to InvalidStructure" {
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = "keyId",
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "valid parsed presentation should separate revoked and valid credentials" {
        val presentationResults = holder.createPresentation(
            challenge = challenge,
            audienceId = verifier.keyPair.identifier,
            presentationDefinition = singularPresentationDefinition,
        ).getOrNull()
        presentationResults.shouldNotBeNull()
        val vp = presentationResults.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .map { it.vc }
            .forEach {
                issuerCredentialStore.revoke(
                    it.vc.id,
                    FixedTimePeriodProvider.timePeriod
                ) shouldBe true
            }
        val revocationList =
            issuer.issueRevocationListCredential(FixedTimePeriodProvider.timePeriod)
        revocationList.shouldNotBeNull()
        verifier.setRevocationList(revocationList)

        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        result.vp.verifiableCredentials.shouldBeEmpty()
        holderCredentialStore.getCredentials().getOrThrow()
            .shouldHaveSize(1)
    }

    "Manually created and valid presentation is valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
        val validCredentials = credentials
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .filter { validator.checkRevocationStatus(it.vc) != Validator.RevocationStatus.REVOKED }
            .map { it.vcSerialized }
        (validCredentials.isEmpty()) shouldBe false

        val vp = VerifiablePresentation(validCredentials)
        val vpSerialized = vp.toJws(
            challenge = challenge,
            issuerId = holder.keyPair.identifier,
            audienceId = verifier.keyPair.identifier,
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws =
            holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrThrow()
                .serialize()
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
    }

    "Wrong issuer in VP is not valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .map { it.vcSerialized }

        val vp = VerifiablePresentation(credentials)
        val vpSerialized = VerifiablePresentationJws(
            vp = vp,
            challenge = challenge,
            issuer = verifier.keyPair.identifier,
            audience = verifier.keyPair.identifier,
            jwtId = vp.id,
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws =
            holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrThrow()
                .serialize()
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "Wrong jwtId in VP is not valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .map { it.vcSerialized }
        val vp = VerifiablePresentation(credentials)
        val vpSerialized = VerifiablePresentationJws(
            vp = vp,
            challenge = challenge,
            issuer = holder.keyPair.identifier,
            audience = verifier.keyPair.identifier,
            jwtId = "wrong_jwtId",
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws =
            holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrThrow()
                .serialize()
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "Wrong type in VP is not valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .map { it.vcSerialized }
        val vp = VerifiablePresentation(
            id = "urn:uuid:${uuid4()}",
            type = "wrong_type",
            verifiableCredential = credentials
        )

        val vpSerialized = vp.toJws(
            challenge = challenge,
            issuerId = holder.keyPair.identifier,
            audienceId = verifier.keyPair.identifier,
        ).serialize()
        val jwsPayload = vpSerialized.encodeToByteArray()
        val vpJws =
            holderJwsService.createSignedJwt(JwsContentTypeConstants.JWT, jwsPayload).getOrThrow()
                .serialize()
        vpJws.shouldNotBeNull()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }
})
