@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderKeyId
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Clock
import kotlin.random.Random


class ValidatorVpTest : FreeSpec({

    val singularPresentationDefinition = PresentationExchangePresentation(
        CredentialPresentationRequest.PresentationExchangeRequest(
            PresentationDefinition(
                DifInputDescriptor(id = uuid4().toString())
            ),
        ),
    )

    lateinit var validator: ValidatorVcJws
    lateinit var issuer: Issuer
    lateinit var statusListIssuer: StatusListIssuer
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holder: HolderAgent
    lateinit var verifiablePresentationFactory: VerifiablePresentationFactory
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderSignVp: SignJwtFun<VerifiablePresentationJws>
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var verifierId: String
    lateinit var verifier: Verifier
    lateinit var challenge: String

    beforeEach {
        validator = ValidatorVcJws(
            validator = Validator(
                tokenStatusResolver = TokenStatusResolverImpl(
                    resolveStatusListToken = {
                        if (Random.nextBoolean()) StatusListToken.StatusListJwt(
                            statusListIssuer.issueStatusListJwt(),
                            resolvedAt = Clock.System.now()
                        ) else {
                            StatusListToken.StatusListCwt(
                                statusListIssuer.issueStatusListCwt(),
                                resolvedAt = Clock.System.now()
                            )
                        }
                    },
                )
            )
        )
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        issuer = IssuerAgent(issuerCredentialStore = issuerCredentialStore)
        statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        holderCredentialStore = InMemorySubjectCredentialStore()
        holderKeyMaterial = EphemeralKeyWithoutCert()
        holder = HolderAgent(
            holderKeyMaterial,
            holderCredentialStore,
            validatorVcJws = validator,
        )
        verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
        holderSignVp = SignJwt(holderKeyMaterial, JwsHeaderKeyId())
        verifierId = "urn:${uuid4()}"
        verifier = VerifierAgent(
            identifier = verifierId,
            validatorVcJws = validator
        )
        challenge = uuid4().toString()

        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
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

    "Presentation of VC from different holder is detected" {
        val otherHolderKeyMaterial = EphemeralKeyWithoutCert()
        val otherHolder = HolderAgent(otherHolderKeyMaterial)
        otherHolder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    otherHolderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
        val holderVc = otherHolder.getCredentials()
            .shouldNotBeNull()
            .shouldBeSingleton()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
        val holderVcSerialized = holderVc
            .map { it.vcSerialized }
            .map { it.reversed() }
        val vp = verifiablePresentationFactory.createVcPresentation(
            holderVcSerialized,
            PresentationRequestParameters(nonce = challenge, audience = verifierId)
        ).shouldBeInstanceOf<CreatePresentationResult.Signed>()

        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge).also {
            it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
            it.vp.freshVerifiableCredentials.shouldBeEmpty()
            it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
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
                    timePeriod = FixedTimePeriodProvider.timePeriod,
                    index = it.vc.credentialStatus!!.statusList.index,
                    status = TokenStatus.Invalid,
                ) shouldBe true
            }

        verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge).also {
            it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
            it.vp.freshVerifiableCredentials.shouldBeEmpty()
        }
        holderCredentialStore.getCredentials().getOrThrow()
            .shouldHaveSize(1)
    }

    "Manually created and valid presentation is valid" {
        val credentials = holderCredentialStore.getCredentials().getOrThrow()
        val validCredentials = credentials
            .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            .filter {
                validator.checkRevocationStatus(it.vc) !is TokenStatusValidationResult.Invalid
            }
            .map { it.vcSerialized }
        (validCredentials.isEmpty()) shouldBe false

        val vp = VerifiablePresentation(validCredentials)
        val vpSerialized = vp.toJws(
            challenge = challenge,
            issuerId = holder.keyMaterial.identifier,
            audienceId = verifierId,
        )
        val vpJws = holderSignVp(
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
            issuer = holder.keyMaterial.identifier,
            audience = verifierId,
            jwtId = "wrong_jwtId",
        )
        val vpJws = holderSignVp(
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
            issuerId = holder.keyMaterial.identifier,
            audienceId = verifierId,
        )
        val vpJws = holderSignVp(
            JwsContentTypeConstants.JWT,
            vpSerialized,
            VerifiablePresentationJws.serializer()
        ).getOrThrow()

        verifier.verifyPresentationVcJwt(vpJws, challenge)
            .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
    }
})
