package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.AuthenticationResponseParameters
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.utils.DefaultMapStore
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking

val OpenId4VpSdJwtProtocolTest by matrixSuite {

    fixture {
        runBlocking {
            val euPidSdJwtScheme = AttributeIndex.resolveIdentifier(EU_PID_SD_JWT_VCT, SD_JWT)
            val holderKeyMaterial = EphemeralKeyWithoutCert()
            val holderAgent = HolderAgent(holderKeyMaterial).also {
                issueAndStoreSdJwt(it, holderKeyMaterial)
                issueAndStoreSdJwt(it, holderKeyMaterial, euPidSdJwtScheme)
            }
            object {
                val euPidSdJwtScheme = euPidSdJwtScheme
                val verifierKeyMaterial = EphemeralKeyWithoutCert()
                val clientId = "https://example.com/rp/${uuid4()}"
                val walletUrl = "https://example.com/wallet/${uuid4()}"

                val holderOid4vp = OpenId4VpHolder(
                    holder = holderAgent,
                    randomSource = RandomSource.Default,
                )
                val stateToAuthnRequestStore = DefaultMapStore<String, AuthenticationRequestParameters>()
                val verifierOid4vp = OpenId4VpVerifier(
                    keyMaterial = verifierKeyMaterial,
                    clientIdScheme = ClientIdScheme.RedirectUri(clientId),
                    stateToAuthnRequestStore = stateToAuthnRequestStore,
                )
            }
        }
    } - {

        "Selective Disclosure with custom credential" {
            val requestedClaim = CLAIM_GIVEN_NAME
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(requestedClaim))
                        )
                    ).toDCQLRequest(),
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            authnRequest shouldContain requestedClaim

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values
                .shouldBeSingleton().first().shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    reconstructedJsonObject[requestedClaim].shouldNotBeNull()
                }
        }

        "authn response nonce cannot be replayed" {
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                        )
                    ).toDCQLRequest(),
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).isFailure shouldBe true
        }

        "a rejected response consumes the request, so the genuine one is not accepted afterwards" {
            val state = uuid4().toString()
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                        )
                    ).toDCQLRequest(),
                    state = state,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            // anyone knowing the state may post a response: this one carries no vp_token and is not accepted,
            // but it burns the request, as authentication responses are never retryable
            it.verifierOid4vp.validateAuthnResponse(
                ResponseParametersFrom.Post(AuthenticationResponseParameters(state = state))
            ).getOrThrow().vpTokenValidationResult.shouldNotBeNull().isFailure shouldBe true

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).isFailure shouldBe true
        }

        "the challenge is consumed even when the response is rejected" {
            val state = uuid4().toString()
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = SD_JWT,
                            attributePaths = setOf(DCQLClaimsPathPointer(CLAIM_GIVEN_NAME))
                        )
                    ).toDCQLRequest(),
                    state = state,
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
            val storedRequest = it.stateToAuthnRequestStore.get(state).shouldNotBeNull()

            it.verifierOid4vp.validateAuthnResponse(
                ResponseParametersFrom.Post(AuthenticationResponseParameters(state = state))
            ).getOrThrow().vpTokenValidationResult.shouldNotBeNull().isFailure shouldBe true

            // restore the stored request, so only the consumed challenge can reject the genuine response
            it.stateToAuthnRequestStore.put(state, storedRequest)
            it.verifierOid4vp.validateAuthnResponse(authnResponse.url)
                .exceptionOrNull().shouldNotBeNull().message shouldContain "nonce invalid or already used"
        }

        "Selective Disclosure with EU PID credential" {
            val requestedClaims = setOf(
                EuPidSdJwtDataElements.FAMILY_NAME,
                EuPidSdJwtDataElements.GIVEN_NAME,
                EuPidSdJwtDataElements.FAMILY_NAME_BIRTH,
                EuPidSdJwtDataElements.GIVEN_NAME_BIRTH,
            )
            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                OpenId4VpRequestOptions(
                    presentationRequest = CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = it.euPidSdJwtScheme,
                            representation = SD_JWT,
                            attributePaths = requestedClaims.map { DCQLClaimsPathPointer(it) }.toSet()
                        )
                    ).toDCQLRequest(),
                ),
                CreationOptions.Query(it.walletUrl)
            ).getOrThrow().url

            val authnResponse = it.holderOid4vp.createAuthnResponse(authnRequest).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()

            it.verifierOid4vp.validateAuthnResponse(authnResponse.url).getOrThrow()
                .vpTokenValidationResult.shouldNotBeNull().getOrThrow()
                .shouldBeInstanceOf<VpTokenValidationResultDCQL>()
                .credentialQueryResponseValidations.values
                .shouldBeSingleton().first()
                .shouldBeSingleton().first().getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    verifiableCredentialSdJwt.shouldNotBeNull()
                    requestedClaims.forEach {
                        it.shouldBeIn(reconstructedJsonObject.keys)
                        reconstructedJsonObject[it].shouldNotBeNull()
                    }
                }

        }
    }
}
