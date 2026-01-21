package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryInstance
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJwtVcCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf


val AgentTest by testSuite {

    withFixtureGenerator {
        object {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val holderCredentialStore = InMemorySubjectCredentialStore()

            val issuerIdentifier = "https://issuer.example.com/${uuid4()}"
            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = issuerIdentifier.toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val validator = Validator(
                tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer)
            )
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val verifierId = "urn:${uuid4()}"
            val holder = HolderAgent(
                holderKeyMaterial, holderCredentialStore,
                validator = validator,
            )
            val verifier = VerifierAgent(
                identifier = verifierId,
                validatorVcJws = ValidatorVcJws(validator = validator),
                validatorSdJwt = ValidatorSdJwt(validator = validator),
                validatorMdoc = ValidatorMdoc(validator = validator),
            )
            val challenge = uuid4().toString()
        }
    } - {
        val singularPresentationDefinition = PresentationExchangePresentation(
            CredentialPresentationRequest.PresentationExchangeRequest(
                PresentationDefinition(
                    DifInputDescriptor(id = uuid4().toString())
                ),
            ),
        )

        test("presex: simple walk-through success") {
            it.holder.storeCredential(
                it.issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            it.holder.getCredentials()?.size shouldBe 1

            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId
                ),
                credentialPresentation = singularPresentationDefinition,
            ).getOrThrow()
                .shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }

        test("presex: wrong keyId in presentation leads to error") {
            it.holder.storeCredential(
                it.issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.issuerIdentifier
                ),
                credentialPresentation = singularPresentationDefinition,
            ).getOrThrow()
                .shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        test("presex: getting credentials when there are no credentials stored") {
            val holderCredentials = it.holder.getCredentials()
            holderCredentials.shouldNotBeNull()
            holderCredentials.shouldBeEmpty()
        }

        test("presex: getting credentials when they are valid") {
            val credentials = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            it.holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
                .shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Vc>()

            it.holderCredentialStore.getCredentials().getOrThrow().shouldHaveSize(1)
            it.holder.getCredentials()
                .shouldNotBeNull()
                .shouldHaveSize(1)
                .forEach { storeEntry ->
                    it.validator.checkRevocationStatus(storeEntry)
                        .shouldBeInstanceOf<TokenStatusValidationResult.Valid>()
                }
        }

        test("presex: getting credentials when the issuer has revoked them") {
            val credential = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            it.holder.storeCredential(credential.toStoreCredentialInput())
                .getOrThrow()
                .shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Vc>()

            it.statusListIssuer.revokeCredential(
                FixedTimePeriodProvider.timePeriod,
                credential.vc.credentialStatus.shouldBeInstanceOf<StatusListInfo>().index
            ) shouldBe true

            it.holder.getCredentials()
                .shouldNotBeNull()
                .forEach { storeEntry ->
                    it.validator.checkRevocationStatus(storeEntry)
                        .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
        }

        test("presex: building presentation without necessary credentials") {
            it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = "urn:${uuid4()}"
                ),
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull() shouldBe null
        }

        test("presex: valid presentation is valid") {
            val credentials = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            it.holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId
                ),
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull()
                .shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldNotBeNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .also {
                    it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
                    it.vp.invalidVerifiableCredentials.shouldBeEmpty()
                    it.vp.freshVerifiableCredentials shouldHaveSize 1
                }
        }

        test("presex: valid presentation is valid -- some other attributes revoked") {
            val credentials = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            it.holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId
                ),
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull()
                .shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldNotBeNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()

            val credentialToRevoke = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
            it.statusListIssuer.revokeCredential(
                FixedTimePeriodProvider.timePeriod,
                credentialToRevoke.vc.credentialStatus.shouldBeInstanceOf<StatusListInfo>().index
            ) shouldBe true

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }

        val singularDCQLRequest = DCQLQuery(
            credentials = DCQLCredentialQueryList(
                DCQLCredentialQueryInstance(
                    id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                    format = CredentialFormatEnum.JWT_VC,
                    meta = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                        typeValues = listOf(
                            listOf(
                                VERIFIABLE_CREDENTIAL,
                                ConstantIndex.AtomicAttribute2023.vcType
                            )
                        )
                    )
                )
            ),
        )

        test("dcql: simple walk-through success") {
            it.holder.storeCredential(
                it.issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            it.holder.getCredentials()?.size shouldBe 1
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    singularDCQLRequest
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters
            val vp = presentationParameters.verifiablePresentations.values.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }

        test("dcql: wrong keyId in presentation leads to error") {
            it.holder.storeCredential(
                it.issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        it.holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.issuerIdentifier,
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    singularDCQLRequest
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters
            val vp = presentationParameters.verifiablePresentations.values.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        test("dcql: building presentation without necessary credentials") {
            it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = "urn:${uuid4()}"
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    singularDCQLRequest
                ),
            ).getOrNull() as PresentationResponseParameters.DCQLParameters? shouldBe null
        }

        test("dcql: valid presentation is valid") {
            val credentials = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            it.holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    singularDCQLRequest
                )
            ).getOrNull() as PresentationResponseParameters.DCQLParameters?
            presentationParameters.shouldNotBeNull()
            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
                .shouldNotBeNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                .also {
                    it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
                    it.vp.freshVerifiableCredentials shouldHaveSize 1
                }
        }

        test("dcql: valid presentation is valid -- some other attributes revoked") {
            val credentials = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            it.holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    singularDCQLRequest
                )
            ).getOrNull() as PresentationResponseParameters.DCQLParameters?
            presentationParameters.shouldNotBeNull()
            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
                .shouldNotBeNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()

            val credentialToRevoke = it.issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    it.holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
                .shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

            it.statusListIssuer.revokeCredential(
                FixedTimePeriodProvider.timePeriod,
                credentialToRevoke.vc.credentialStatus.shouldBeInstanceOf<StatusListInfo>().index
            ) shouldBe true

            it.verifier.verifyPresentationVcJwt(vp.jwsSigned, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }
    }
}