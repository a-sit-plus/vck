@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
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

    val singularPresentationDefinition = PresentationExchangePresentation(
        CredentialPresentationRequest.PresentationExchangeRequest(
            PresentationDefinition(
                DifInputDescriptor(id = uuid4().toString())
            ),
        ),
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
            request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
            credentialPresentation = singularPresentationDefinition,
        ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

        val vp = presentationParameters.presentationResults.first()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()
        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.Success>()
    }

    "wrong structure of VC is detected" {
        val holderCredentials = holder.getCredentials()
        holderCredentials.shouldNotBeNull()
        val holderVcSerialized = holderCredentials
            .filterIsInstance<Holder.StoredCredential.Vc>()
            .map { it.storeEntry.vcSerialized }
            .map { it.reversed() }
        val vp = holder.createVcPresentation(
            holderVcSerialized,
            PresentationRequestParameters(nonce = challenge, audience = verifierId)
        ).getOrThrow()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()

        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge).also {
            it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
            it.vp.verifiableCredentials.shouldBeEmpty()
            it.vp.revokedVerifiableCredentials.shouldBeEmpty()
            it.vp.invalidVerifiableCredentials.shouldBe(holderVcSerialized)
        }
    }

    "wrong challenge in VP leads to error" {
        val presentationParameters = holder.createPresentation(
            request = PresentationRequestParameters(nonce = "challenge", audience = verifierId),
            credentialPresentation = singularPresentationDefinition,
        ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()
        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
    }

    "wrong audience in VP leads to error" {
        val presentationParameters = holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = "keyId"),
            credentialPresentation = singularPresentationDefinition,
        ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

        val vp = presentationParameters.presentationResults.first()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()
        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
    }

    "valid parsed presentation should separate revoked and valid credentials" {
        val presentationResults = holder.createPresentation(
            request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
            credentialPresentation = singularPresentationDefinition,
        ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

        val vp = presentationResults.presentationResults.first()
            .shouldBeInstanceOf<CreatePresentationResult.Signed>()
        holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .map { it.vc }
            .forEach {
                issuerCredentialStore.setStatus(
                    it.vc.id,
                    TokenStatus.Invalid,
                    FixedTimePeriodProvider.timePeriod
                ) shouldBe true
            }

        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge).also {
            it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
            it.vp.verifiableCredentials.shouldBeEmpty()
        }
        holderCredentialStore.getCredentials().getOrThrow()
            .shouldHaveSize(1)
    }

    "Manually created and valid presentation is valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
        val validCredentials = credentials
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .filter { validator.checkRevocationStatus(it.vc)?.getOrNull() != TokenStatus.Invalid }
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
        ).getOrThrow()

        verifier.verifyPresentationVcJwt(vpJws, challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.Success>()
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

        verifier.verifyPresentationVcJwt(vpJws, challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
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

        verifier.verifyPresentationVcJwt(vpJws, challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
    }
})
