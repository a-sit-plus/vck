@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryInstance
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
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
            validator = validator,
            issuerCredentialStore = issuerCredentialStore,
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

    "when using presentation exchange" - {
        val singularPresentationDefinition = PresentationExchangePresentation(
            CredentialPresentationRequest.PresentationExchangeRequest(
                PresentationDefinition(
                    DifInputDescriptor(id = uuid4().toString())
                ),
            ),
        )

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
                credentialPresentation = singularPresentationDefinition,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            val verified = verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }

        "wrong keyId in presentation leads to error" {
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
                request = PresentationRequestParameters(
                    nonce = challenge,
                    audience = issuer.keyMaterial.identifier
                ),
                credentialPresentation = singularPresentationDefinition,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            val result = verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "getting credentials that have been stored by the holder" - {

            "when there are no credentials stored" {
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.shouldBeEmpty()
            }

            "when they are valid" {
                val credentials = issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow()
                credentials.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()

                val storedCredentials = holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
                storedCredentials.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Vc>()

                holderCredentialStore.getCredentials().getOrThrow().shouldHaveSize(1)
                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.shouldHaveSize(1)
                holderCredentials.forEach {
                    validator.checkRevocationStatus(it).shouldBeInstanceOf<TokenStatusValidationResult.Valid>()
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

                val storedCredentials =
                    holder.storeCredential(credentials.toStoreCredentialInput()).getOrThrow()
                storedCredentials.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Vc>()

                issuer.revokeCredentials(listOf(credentials.vcJws)) shouldBe true

                val holderCredentials = holder.getCredentials()
                holderCredentials.shouldNotBeNull()
                holderCredentials.forEach {
                    validator.checkRevocationStatus(it).shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
            }
        }

        "building presentation without necessary credentials" {
            holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = challenge,
                    audience = "urn:${uuid4()}"
                ),
                credentialPresentation = singularPresentationDefinition,
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
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldNotBeNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()

            verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge).also {
                it.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
                it.vp.invalidVerifiableCredentials.shouldBeEmpty()
                it.vp.freshVerifiableCredentials shouldHaveSize 1
            }
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
                credentialPresentation = singularPresentationDefinition,
            ).getOrNull().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldNotBeNull()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()

            val credentialsToRevoke = issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                ).getOrThrow()
            ).getOrThrow()
            credentialsToRevoke.shouldBeInstanceOf<Issuer.IssuedCredential.VcJwt>()
            issuer.revokeCredentials(listOf(credentialsToRevoke.vcJws)) shouldBe true

            verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }
    }

    "when using dcql" - {
        val singularDCQLRequest = DCQLQuery(
            credentials = DCQLCredentialQueryList(
                DCQLCredentialQueryInstance(
                    id = DCQLCredentialQueryIdentifier(uuid4().toString()),
                    format = CredentialFormatEnum.JWT_VC
                )
            ),
        )

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

            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(singularDCQLRequest)
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters
            val vp = presentationParameters.verifiablePresentations.values.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            val verified = verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }

        "wrong keyId in presentation leads to error" {
            holder.storeCredential(
                issuer.issueCredential(
                    DummyCredentialDataProvider.getCredential(
                        holderKeyMaterial.publicKey,
                        ConstantIndex.AtomicAttribute2023,
                        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()

            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = challenge,
                    audience = issuer.keyMaterial.identifier
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(singularDCQLRequest)
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters
            val vp = presentationParameters.verifiablePresentations.values.first()
                .shouldBeInstanceOf<CreatePresentationResult.Signed>()
            val result = verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
            result.shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "building presentation without necessary credentials" {
            holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = challenge,
                    audience = "urn:${uuid4()}"
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(singularDCQLRequest),
            ).getOrNull() as PresentationResponseParameters.DCQLParameters? shouldBe null
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
            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(singularDCQLRequest)
            ).getOrNull() as PresentationResponseParameters.DCQLParameters?
            presentationParameters.shouldNotBeNull()
            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
            vp.shouldNotBeNull()
            vp.shouldBeInstanceOf<CreatePresentationResult.Signed>()

            verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge).also {
                it.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
                it.vp.notVerifiablyFreshVerifiableCredentials.shouldBeEmpty()
                it.vp.freshVerifiableCredentials shouldHaveSize 1
            }
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
            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(singularDCQLRequest)
            ).getOrNull() as PresentationResponseParameters.DCQLParameters?
            presentationParameters.shouldNotBeNull()
            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
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

            verifier.verifyPresentationVcJwt(vp.jwsSigned.getOrThrow(), challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        }
    }
})

