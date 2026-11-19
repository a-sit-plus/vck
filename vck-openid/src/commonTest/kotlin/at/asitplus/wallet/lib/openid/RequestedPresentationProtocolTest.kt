package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryResult
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult
import at.asitplus.openid.dcql.DCQLCredentialQueryMatchingResult.ClaimsQueryResults
import at.asitplus.openid.dcql.DCQLCredentialSubmissionOption
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.ClaimSelection
import at.asitplus.wallet.lib.RequestedCredential
import at.asitplus.wallet.lib.RequestedCredentialSet
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.agent.DCQLMatchingResult
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.openid.DummyCredentialDataProvider.issueAndStoreSdJwt
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * Presents credentials for [RequestedPresentation]s end to end: the holder selects claims and credentials from the
 * DCQL query built by [CredentialPresentationRequestBuilder], and the verifier accepts what it presents, unless it
 * satisfies no claim combination.
 */
val RequestedPresentationProtocolTest by matrixSuite {
    val givenNameJson = JsonClaimReference(CLAIM_GIVEN_NAME)
    val familyNameJson = JsonClaimReference(CLAIM_FAMILY_NAME)
    val dateOfBirthJson = JsonClaimReference(CLAIM_DATE_OF_BIRTH)
    val nicknameJson = JsonClaimReference("nickname") // not issued
    val givenNameMdoc = MdocClaimReference(AtomicAttribute2023, CLAIM_GIVEN_NAME)
    val familyNameMdoc = MdocClaimReference(AtomicAttribute2023, CLAIM_FAMILY_NAME)
    val nicknameMdoc = MdocClaimReference(AtomicAttribute2023, "nickname") // not issued
    val sdJwt = RequestedCredential.SdJwt(AtomicAttribute2023, givenNameJson, id = "sdjwt")
    val mdoc = RequestedCredential.Mdoc(AtomicAttribute2023, givenNameMdoc, id = "mdoc")

    "claim combinations" - {
        fixture { ExchangeFixture() } - {
            test("the first claim combination the credential satisfies is presented") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)

                val request = RequestedCredential.SdJwt(
                    AtomicAttribute2023,
                    ClaimSelection.Alternatives(setOf(givenNameJson), setOf(familyNameJson)),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedClaimNames() shouldBe setOf(CLAIM_GIVEN_NAME)
                }
            }

            test("a later claim combination is presented and accepted if the credential lacks an earlier one") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)

                val request = RequestedCredential.SdJwt(
                    AtomicAttribute2023,
                    ClaimSelection.Alternatives(
                        setOf(nicknameJson),
                        setOf(familyNameJson),
                        common = setOf(givenNameJson),
                    ),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedClaimNames() shouldBe
                            setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME)
                    submissionRequirements() shouldBe CheckOutcome.Passed
                }
            }

            test("claims if available are presented if the credential contains all of them") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)

                val request = RequestedCredential.SdJwt(
                    AtomicAttribute2023,
                    ClaimSelection.All(
                        required = setOf(givenNameJson),
                        ifAvailable = setOf(familyNameJson, dateOfBirthJson),
                    ),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedClaimNames() shouldBe
                            setOf(CLAIM_GIVEN_NAME, CLAIM_FAMILY_NAME, CLAIM_DATE_OF_BIRTH)
                }
            }

            test("claims if available are all omitted if the credential lacks one of them") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)

                val request = RequestedCredential.SdJwt(
                    AtomicAttribute2023,
                    ClaimSelection.All(
                        required = setOf(givenNameJson),
                        ifAvailable = setOf(familyNameJson, nicknameJson),
                    ),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedClaimNames() shouldBe
                            setOf(CLAIM_GIVEN_NAME)
                    submissionRequirements() shouldBe CheckOutcome.Passed
                }
            }

            test("with only claims if available, which the credential lacks, no claim is disclosed") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)

                val request = RequestedCredential.SdJwt(
                    AtomicAttribute2023,
                    ClaimSelection.All(ifAvailable = setOf(nicknameJson)),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedClaimNames().shouldBeEmpty()
                }
            }

            test("data elements if available are all omitted if the mdoc lacks one of them") {
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

                val request = RequestedCredential.Mdoc(
                    AtomicAttribute2023,
                    ClaimSelection.All(
                        required = setOf(givenNameMdoc),
                        ifAvailable = setOf(familyNameMdoc, nicknameMdoc),
                    ),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedIssuerSignedItemIdentifiers() shouldBe
                            setOf(CLAIM_GIVEN_NAME)
                }
            }

            test("alternative data elements of an mdoc are requested by DCQL, the first the mdoc has is presented") {
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

                val request = RequestedCredential.Mdoc(
                    AtomicAttribute2023,
                    ClaimSelection.Alternatives(setOf(nicknameMdoc), setOf(givenNameMdoc)),
                )

                it.present(request).apply {
                    singleAcceptedPresentation().disclosedIssuerSignedItemIdentifiers() shouldBe
                            setOf(CLAIM_GIVEN_NAME)
                }
            }

            test("a presentation that satisfies no claim combination is not accepted") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)
                val request = RequestedPresentation.allOf(
                    RequestedCredential.SdJwt(AtomicAttribute2023, givenNameJson, familyNameJson)
                )
                val givenNameOnly = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)

                val result = it.presentWith(request) { matches ->
                    matches.mapValues { entry ->
                        entry.value.take(1).map { option ->
                            option.copy(matchingResult = option.matchingResult.onlySelecting(givenNameOnly))
                        }
                    }
                }

                result.submissionRequirements().shouldBeInstanceOf<CheckOutcome.Failed>()
            }
        }
    }

    "credential sets" - {
        fixture { ExchangeFixture() } - {
            test("a set is satisfied by an option the holder can present") {
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

                val request = RequestedPresentation(RequestedCredentialSet.oneOf(setOf(sdJwt), setOf(mdoc)))

                it.present(request).apply {
                    acceptedPresentationIdentifiers() shouldBe setOf(mdoc.id)
                    submissionRequirements() shouldBe CheckOutcome.Passed
                }
            }

            test("the default submission presents the first option the holder can present") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

                val request = RequestedPresentation(RequestedCredentialSet.oneOf(setOf(sdJwt, mdoc), setOf(sdJwt)))

                it.present(request).apply {
                    acceptedPresentationIdentifiers() shouldBe setOf(sdJwt.id, mdoc.id)
                }
            }

            test("the default submission does not present optional sets") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)

                val request = RequestedPresentation(
                    RequestedCredentialSet.oneOf(setOf(sdJwt)),
                    RequestedCredentialSet.optional(setOf(mdoc)),
                )

                it.present(request).apply {
                    acceptedPresentationIdentifiers() shouldBe setOf(sdJwt.id)
                }
            }

            test("a submission built by the wallet may present optional sets") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
                
                val request = RequestedPresentation(
                    RequestedCredentialSet.oneOf(setOf(sdJwt)),
                    RequestedCredentialSet.optional(setOf(mdoc)),
                )

                it.presentWith(request) { matches -> matches.mapValues { entry -> entry.value.take(1) } }.apply {
                    acceptedPresentationIdentifiers() shouldBe setOf(sdJwt.id, mdoc.id)
                    submissionRequirements() shouldBe CheckOutcome.Passed
                }
            }

            test("a submission without an option of every required set is not presented, the holder answers an error") {
                issueAndStoreSdJwt(it.holderAgent, it.holderKeyMaterial)
                issueAndStoreIsoMdoc(it.holderAgent, it.holderKeyMaterial, AtomicAttribute2023)
                val request = RequestedPresentation(
                    RequestedCredentialSet.oneOf(setOf(sdJwt)),
                    RequestedCredentialSet.optional(setOf(mdoc)),
                )

                val result = it.presentWith(request) { matches ->
                    matches.filterKeys { id -> id.string == mdoc.id }.mapValues { entry -> entry.value.take(1) }
                }

                result.shouldBeInstanceOf<AuthnResponseResult.Error>()
            }
        }
    }
}

/** A holder with an empty credential store and a verifier, new for each test. */
private class ExchangeFixture {
    val holderKeyMaterial: KeyMaterial = EphemeralKeyWithoutCert()
    val holderAgent: Holder = HolderAgent(holderKeyMaterial)
    val holderOid4vp = OpenId4VpHolder(holder = holderAgent, randomSource = RandomSource.Default)
    val verifierOid4vp = OpenId4VpVerifier(
        keyMaterial = EphemeralKeyWithoutCert(),
        clientIdScheme = ClientIdScheme.RedirectUri("https://example.com/rp/${uuid4()}"),
        presentationPolicy = testPresentationPolicy,
    )

    suspend fun authnRequest(presentation: RequestedPresentation) = verifierOid4vp.createAuthnRequest(
        requestOptions = OpenId4VpRequestOptions(CredentialPresentationRequestBuilder(presentation).toDCQLRequest()),
        creationOptions = CreationOptions.Query("https://example.com"),
    ).getOrThrow().url

    /** Presents what the holder's default submission selects, and validates it as the verifier. */
    suspend fun present(presentation: RequestedPresentation): AuthnResponseResult {
        val response = holderOid4vp.createAuthorizationResponse(authnRequest(presentation)).getOrThrow()
            .shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        return verifierOid4vp.validateAuthnResponse(response.url).getOrThrow()
    }

    suspend fun present(credential: RequestedCredential) = present(RequestedPresentation.allOf(credential))

    /**
     * Presents the submission that [select] builds from the holder's matching credentials for each credential query,
     * as a wallet does that lets the End-User choose, and validates it as the verifier.
     */
    suspend fun presentWith(
        presentation: RequestedPresentation,
        select: (matches: Submissions) -> Submissions,
    ): AuthnResponseResult {
        val preparationState = holderOid4vp.prepareAuthorizationResponse(authnRequest(presentation)).getOrThrow()
        val dcqlRequest = preparationState.credentialPresentationRequest.shouldBeInstanceOf<DCQLRequest>()
        val matches = holderAgent.matchPresentationRequestAgainstCredentialStore(dcqlRequest).getOrThrow()
            .shouldBeInstanceOf<DCQLMatchingResult<SubjectCredentialStore.StoreEntry>>()
            .matchingResult.credentialQueryMatches
        val response = holderOid4vp.finalizeAuthorizationResponse(
            preparationState = preparationState,
            credentialPresentation = CredentialPresentation.DCQLPresentation(
                presentationRequest = dcqlRequest,
                credentialQuerySubmissions = select(matches),
            ),
        ).getOrThrow().shouldBeInstanceOf<AuthenticationResponseResult.Redirect>()
        return verifierOid4vp.validateAuthnResponse(response.url).getOrThrow()
    }
}

/** The credentials a holder submits, or may submit, for each credential query. */
private typealias Submissions =
        Map<DCQLCredentialQueryIdentifier, List<DCQLCredentialSubmissionOption<SubjectCredentialStore.StoreEntry>>>

/**
 * This matching result reduced to the claims queries that select [path], so a presentation built from it withholds
 * the claims of the others.
 */
private fun DCQLCredentialQueryMatchingResult.onlySelecting(path: DCQLClaimsPathPointer) = ClaimsQueryResults(
    shouldBeInstanceOf<ClaimsQueryResults>().claimsQueryResults.filter { result ->
        result.shouldBeInstanceOf<DCQLClaimsQueryResult.JsonResult>().selectedClaims.any { it.path == path }
    }
)

/** The names of the object properties this accepted SD-JWT presentation discloses. */
private fun ValidatedPresentation.disclosedClaimNames() =
    sdJwtVc.decoded.validDisclosures.values.mapNotNull { it.claimName }.toSet()

/** The names of issuer signed items this accepted ISO mDoc presentation discloses. */
private fun ValidatedPresentation.disclosedIssuerSignedItemIdentifiers() =
    issuerSignedItems.map { item -> item.elementIdentifier }.toSet()

/** The IDs of the credential queries this processed response presents accepted credentials for. */
private fun AuthnResponseResult.acceptedPresentationIdentifiers() =
    acceptedPresentations().keys.map { it.string }.toSet()