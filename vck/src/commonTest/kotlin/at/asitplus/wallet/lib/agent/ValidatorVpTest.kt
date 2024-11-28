@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
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
import kotlinx.datetime.Clock
import kotlin.random.Random


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
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierId: String
    lateinit var verifier: Verifier
    lateinit var challenge: String

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
        issuer = IssuerAgent(
            EphemeralKeyWithoutCert(),
            issuerCredentialStore,
            validator = validator,
        )
        holderCredentialStore = InMemorySubjectCredentialStore()
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holder = HolderAgent(
            holderKeyMaterial,
            holderCredentialStore,
            validator = validator,
        )
        holderJwsService = DefaultJwsService(DefaultCryptoService(holderKeyMaterial))
        verifierId = "urn:${uuid4()}"
        verifier = VerifierAgent(
            identifier = verifierId,
            validator = validator,
        )
        challenge = uuid4().toString()

        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
    }

    "correct challenge in VP leads to Success" {
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifierId,
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
        val vp = holder.createVcPresentation(holderVcSerialized, challenge, verifierId).getOrNull()
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
            audienceId = verifierId,
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
        ).getOrThrow()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp.shouldNotBeNull()
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.Signed>()
        val result = verifier.verifyPresentation(vp.jws, challenge)
        result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "valid parsed presentation should separate revoked and valid credentials" {
        val presentationResults = holder.createPresentation(
            challenge = challenge,
            audienceId = verifierId,
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
                issuerCredentialStore.setStatus(
                    it.vc.id,
                    status = TokenStatus.Invalid,
                    FixedTimePeriodProvider.timePeriod
                ) shouldBe true
            }

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
            .filter { validator.checkRevocationStatus(it.vc) != TokenStatus.Invalid }
            .map { it.vcSerialized }
        (validCredentials.isEmpty()) shouldBe false

        val vp = VerifiablePresentation(validCredentials)
        val vpSerialized = vp.toJws(
            challenge = challenge,
            issuerId = holder.keyPair.identifier,
            audienceId = verifierId,
        )
        val vpJws = holderJwsService.createSignedJwt(
            JwsContentTypeConstants.JWT,
            vpSerialized,
            VerifiablePresentationJws.serializer()
        ).getOrThrow().serialize()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
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
            audience = verifierId,
            jwtId = "wrong_jwtId",
        )
        val vpJws = holderJwsService.createSignedJwt(
            JwsContentTypeConstants.JWT,
            vpSerialized,
            VerifiablePresentationJws.serializer()
        ).getOrThrow()
            .serialize()

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
            audienceId = verifierId,
        )
        val vpJws = holderJwsService.createSignedJwt(
            JwsContentTypeConstants.JWT,
            vpSerialized,
            VerifiablePresentationJws.serializer()
        ).getOrThrow()
            .serialize()

        verifier.verifyPresentation(vpJws, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }
})
