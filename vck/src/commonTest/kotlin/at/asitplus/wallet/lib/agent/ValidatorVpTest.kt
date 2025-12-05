package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.VerifiablePresentation
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf


val ValidatorVpTest by testSuite {

    val singularPresentationDefinition = PresentationExchangePresentation(
        CredentialPresentationRequest.PresentationExchangeRequest(
            PresentationDefinition(
                DifInputDescriptor(id = uuid4().toString())
            ),
        ),
    )

    withFixtureGenerator(suspend {
        val holderCredentialStore = InMemorySubjectCredentialStore()
        val holderKeyMaterial = EphemeralKeyWithoutCert()
        val issuerCredentialStore = InMemoryIssuerCredentialStore()

        val issuer = IssuerAgent(
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )

        val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)

        val validator = ValidatorVcJws(
            validator = Validator(
                tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer)
            )
        )
        val holder = HolderAgent(
            holderKeyMaterial,
            holderCredentialStore,
            validatorVcJws = validator,
        ).also {
            it.storeCredential(
                issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()
        }
        object {
            val issuer = issuer
            val holderCredentialStore = holderCredentialStore
            val issuerCredentialStore = issuerCredentialStore
            val validator = validator

            val holder = holder
            val verifiablePresentationFactory = VerifiablePresentationFactory(holderKeyMaterial)
            val holderSignVp = SignJwt<VerifiablePresentationJws>(holderKeyMaterial, JwsHeaderCertOrJwk())
            val verifierId = "urn:${uuid4()}"
            val verifier = VerifierAgent(
                identifier = verifierId,
                validatorVcJws = validator
            )
            val challenge = uuid4().toString()
        }
    }) - {

        "correct challenge in VP leads to Success" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.Success>()
        }

        "Presentation of VC from different holder is detected" {
            val otherHolderKeyMaterial = EphemeralKeyWithoutCert()
            val otherHolder = HolderAgent(otherHolderKeyMaterial)
            otherHolder.storeCredential(
                it.issuer.issueCredential(
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
            val vp = it.verifiablePresentationFactory.createVcPresentation(
                holderVc,
                PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId)
            ).shouldBeInstanceOf<CreatePresentationResult.Signed>()

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge).also {
                it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
                it.vp.freshVerifiableCredentials.shouldBeEmpty()
                it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
                it.vp.invalidVerifiableCredentials.shouldBe(holderVc.map { it.vcSerialized })
            }
        }

        "wrong challenge in VP leads to error" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = "challenge", audience = it.verifierId),
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
        }

        "wrong audience in VP leads to error" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = "keyId"),
                credentialPresentation = singularPresentationDefinition,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
        }

        "valid parsed presentation should separate revoked and valid credentials" {
            val presentationResults = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationResults.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
                .map { it.vc }
                .forEach { vcjws ->
                    it.issuerCredentialStore.setStatus(
                        timePeriod = FixedTimePeriodProvider.timePeriod,
                        index = vcjws.vc.credentialStatus.shouldNotBeNull().statusList.shouldNotBeNull().index,
                        status = TokenStatus.Invalid,
                    ) shouldBe true
                }

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge).also {
                it.shouldBeInstanceOf<VerifyPresentationResult.Success>()
                it.vp.freshVerifiableCredentials.shouldBeEmpty()
            }
            it.holderCredentialStore.getCredentials().getOrThrow()
                .shouldHaveSize(1)
        }

        "Manually created and presentation with jwkThumbprint is valid" {
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
            val validCredentials = credentials
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
                .filter { storeEntry ->
                    it.validator.checkRevocationStatus(storeEntry.vc) !is TokenStatusValidationResult.Invalid
                }
                .map { it.vcSerialized }
            (validCredentials.isEmpty()) shouldBe false

            val vp = VerifiablePresentation(validCredentials)
            val vpSerialized = vp.toJws(
                challenge = it.challenge,
                issuerId = it.holder.keyMaterial.jsonWebKey.jwkThumbprint,
                audienceId = it.verifierId,
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            it.verifier.verifyPresentationVcJwt(vpJws, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.Success>()
        }

        "Manually created and presentation with did is valid" {
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
            val validCredentials = credentials
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
                .filter { storeEntry ->
                    it.validator.checkRevocationStatus(storeEntry.vc) !is TokenStatusValidationResult.Invalid
                }
                .map { it.vcSerialized }
            (validCredentials.isEmpty()) shouldBe false

            val vp = VerifiablePresentation(validCredentials)
            val vpSerialized = vp.toJws(
                challenge = it.challenge,
                issuerId = it.holder.keyMaterial.jsonWebKey.didEncoded!!,
                audienceId = it.verifierId,
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            it.verifier.verifyPresentationVcJwt(vpJws, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.Success>()
        }

        "Wrong jwtId in VP is not valid" {
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            val vp = VerifiablePresentation(credentials.map { it.vcSerialized })
            val vpSerialized = VerifiablePresentationJws(
                vp = vp,
                challenge = it.challenge,
                issuer = credentials.first().vc.vc.credentialSubject.id,
                audience = it.verifierId,
                jwtId = "wrong_jwtId",
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            it.verifier.verifyPresentationVcJwt(vpJws, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
        }

        "Wrong type in VP is not valid" {
            val credentials = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Vc>()
            val vp = VerifiablePresentation(
                id = "urn:uuid:${uuid4()}",
                type = "wrong_type",
                verifiableCredential = credentials.map { it.vcSerialized }
            )

            val vpSerialized = vp.toJws(
                challenge = it.challenge,
                issuerId = credentials.first().vc.vc.credentialSubject.id,
                audienceId = it.verifierId,
            )
            val vpJws = it.holderSignVp(
                JwsContentTypeConstants.JWT,
                vpSerialized,
                VerifiablePresentationJws.serializer()
            ).getOrThrow()

            it.verifier.verifyPresentationVcJwt(vpJws, it.challenge)
                .shouldBeInstanceOf<VerifyPresentationResult.ValidationError>()
        }
    }
}