package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.DCQLPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf

val OpenId4VpCombinedProtocolTwoStepTest by matrixSuite {

    fixture {
        object {
            val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val verifierKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
            val clientId: String = "https://example.com/rp/${uuid4()}"
            val holderAgent: Holder = HolderAgent(holderKeyMaterial)
            val holderOid4vp: OpenId4VpHolder = OpenId4VpHolder(
                keyMaterial = holderKeyMaterial,
                holder = holderAgent,
                randomSource = RandomSource.Default,
            )
            val verifierOid4vp: OpenId4VpVerifier = OpenId4VpVerifier(
                keyMaterial = verifierKeyMaterial,
                clientIdScheme = ClientIdScheme.RedirectUri(clientId),
            )
        }
    } - {

        test("matching: only credentials of the correct format are matched") {
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)


            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    ).toDCQLRequest(),
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState = it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest)
                .getOrThrow()
            val dcqlQuery = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<DCQLRequest>()
                .dcqlQuery
            val credentialQueryId = dcqlQuery.credentials.first().id

            it.holderAgent.matchDCQLQueryAgainstCredentialStoreV2(dcqlQuery)
                .getOrThrow().also {
                    it.dcqlQueryMatchingResult.credentialMatchingResults.forEach {
                        it.value.shouldHaveSize(3)
                    }
                }.credentialQueryMatches[credentialQueryId]
                .shouldNotBeNull().apply {
                    this shouldHaveSize 2
                    forEach {
                        it.credential.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.Iso>()
                    }
                }
        }

        test("submission requirements need to match: all credentials matching a credential query should be presentable") {
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)


            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    ).toDCQLRequest(),
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState = it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest)
                .getOrThrow()
            val dcqlRequest = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<DCQLRequest>()
            val credentialQueryId = dcqlRequest.dcqlQuery.credentials.first().id

            val matches = it.holderAgent.matchDCQLQueryAgainstCredentialStoreV2(dcqlRequest.dcqlQuery)
                .getOrThrow().also {
                    it.dcqlQueryMatchingResult.credentialMatchingResults.forEach {
                        it.value.shouldHaveSize(3) // 2x iso, 1x sdJwt
                    }
                }.credentialQueryMatches.also { it shouldHaveSize 1 }

            val credentialQueryMatches = matches[credentialQueryId].shouldNotBeNull()
                .also { it shouldHaveSize 2 }

            val fx = it
            credentialQueryMatches.forEach { match ->
                shouldNotThrowAny {
                    fx.holderOid4vp.finalizeAuthorizationResponse(
                        preparationState = preparationState,
                        credentialPresentation = DCQLPresentation(
                            presentationRequest = dcqlRequest,
                            credentialQuerySubmissions = mapOf(credentialQueryId to listOf(match))
                        )
                    ).getOrThrow()
                }
            }
        }

        test("submission requirements need to match: not all optional claims need to be presented") {
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(
                            credentialScheme = AtomicAttribute2023,
                            representation = ISO_MDOC,
                            optionalAttributePaths = setOf(
                                DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_FAMILY_NAME),
                                DCQLClaimsPathPointer(AtomicAttribute2023.CLAIM_GIVEN_NAME)
                            ),
                        )
                    ).toDCQLRequest(),
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState = it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest)
                .getOrThrow()
            val dcqlRequest = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<DCQLRequest>()
            val credentialQueryId = dcqlRequest.dcqlQuery.credentials.first().id

            val matches = it.holderAgent.matchDCQLQueryAgainstCredentialStoreV2(dcqlRequest.dcqlQuery)
                .getOrThrow().also {
                    it.dcqlQueryMatchingResult.credentialMatchingResults.forEach {
                        it.value.shouldHaveSize(1)
                    }
                }.credentialQueryMatches.also { it shouldHaveSize 1 }

            val match = matches[credentialQueryId].shouldNotBeNull()
                .shouldBeSingleton().first()

            val givenNameOnly = match.matchingResult
                .shouldBeInstanceOf<DCQLCredentialQueryMatchingResult.ClaimsQueryResults>()
                .claimsQueryResults.filter {
                    it.shouldBeInstanceOf<DCQLClaimsQueryResult.IsoMdocResult>()
                        .claimName == AtomicAttribute2023.CLAIM_GIVEN_NAME
                }.also { it shouldHaveSize 1 }

            shouldNotThrowAny {
                it.holderOid4vp.finalizeAuthorizationResponse(
                    preparationState = preparationState,
                    credentialPresentation = DCQLPresentation(
                        presentationRequest = dcqlRequest,
                        credentialQuerySubmissions = mapOf(
                            credentialQueryId to listOf(
                                match.copy(
                                    matchingResult = DCQLCredentialQueryMatchingResult.ClaimsQueryResults(
                                        givenNameOnly
                                    )
                                )
                            )
                        )
                    )
                ).getOrThrow()
            }
        }


        test("submission requirements need to match: credentials not matching a credential query should not yield a valid submission") {
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
            issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
            issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

            val sdJwtRequest = CredentialPresentationRequestBuilder(
                RequestOptionsCredential(AtomicAttribute2023, SD_JWT)
            ).toDCQLRequest().shouldNotBeNull()

            val sdJwtMatches = it.holderAgent.matchDCQLQueryAgainstCredentialStoreV2(sdJwtRequest.dcqlQuery)
                .getOrThrow().also {
                    it.dcqlQueryMatchingResult.credentialMatchingResults.forEach {
                        it.value.shouldHaveSize(3)
                    }
                }.credentialQueryMatches.also {
                    it shouldHaveSize 1
                    it.values.first().shouldBeSingleton().first()
                        .credential.shouldBeInstanceOf<SubjectCredentialStore.StoreEntry.SdJwt>()
                }

            val authnRequest = it.verifierOid4vp.createAuthnRequest(
                requestOptions = OpenId4VpRequestOptions(
                    CredentialPresentationRequestBuilder(
                        RequestOptionsCredential(AtomicAttribute2023, ISO_MDOC)
                    ).toDCQLRequest(),
                ),
                creationOptions = CreationOptions.Query("https://example.com")
            ).getOrThrow().url

            val preparationState = it.holderOid4vp.startAuthorizationResponsePreparation(authnRequest)
                .getOrThrow()
            val dcqlRequest = preparationState.credentialPresentationRequest
                .shouldBeInstanceOf<DCQLRequest>()
            val credentialQueryId = dcqlRequest.dcqlQuery.credentials.first().id

            val matches = it.holderAgent.matchDCQLQueryAgainstCredentialStoreV2(dcqlRequest.dcqlQuery)
                .getOrThrow().also {
                    it.dcqlQueryMatchingResult.credentialMatchingResults.forEach {
                        it.value.shouldHaveSize(3)
                    }
                }.credentialQueryMatches.also { it shouldHaveSize 1 }

            matches[credentialQueryId].shouldNotBeNull().shouldHaveSize(2)

            it.holderOid4vp.finalizeAuthorizationResponse(
                preparationState = preparationState,
                credentialPresentation = DCQLPresentation(
                    presentationRequest = dcqlRequest,
                    credentialQuerySubmissions = sdJwtMatches
                )
            ).getOrThrow()
                .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
                .error.shouldNotBeNull()
        }
    }
}

private fun AuthenticationRequestParameters.serialize(): String = joseCompliantSerializer.encodeToString(this)
