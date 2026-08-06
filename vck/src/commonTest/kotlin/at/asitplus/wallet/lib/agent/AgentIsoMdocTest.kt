package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.Document
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import io.github.z4kn4fein.semver.Version
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.datetime.LocalDate

val AgentIsoMdocTest by matrixSuite {

    for (mode in IsoRevocationMode.entries) {
        fixture { runBlocking { createIsoMdocFixture(mode) } } - {
            "dcql: simple walk-through success${mode.testNameSuffix}" {
                val vp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)

                it.verifyPresentation(vp).apply {
                    assertPresentedClaims(expectDateOfBirth = true)
                    assertRevocationInvalid(expectedInvalid = false)
                }
            }

            "dcql: revoked credential${mode.testNameSuffix}" {
                val vp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME)

                it.revokeSingleStoredCredential() shouldBe true

                it.verifyPresentation(vp).apply {
                    assertPresentedClaims(expectDateOfBirth = false)
                    assertRevocationInvalid(expectedInvalid = true)
                }
            }

            if (mode == IsoRevocationMode.STATUS_LIST) {
                "device retrieval: creates one device response with the requested claim" {
                    val request = it.verifier.createPresentationRequest(
                        calcIsoSessionTranscript = simpleTranscriptCallback,
                    )
                    val result = it.holder.createDefaultPresentation(
                        request = request,
                        credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                            isoDeviceRequest(CLAIM_GIVEN_NAME)
                        )
                    ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

                    result.deviceResponse.documents.shouldNotBeNull().shouldBeSingleton().single()
                        .issuerSigned.namespaces.shouldNotBeNull()
                        .getValue(ConstantIndex.AtomicAttribute2023.isoNamespace).entries.shouldBeSingleton()
                        .single().value.elementIdentifier shouldBe CLAIM_GIVEN_NAME
                    it.verifier.consumeChallenge(request.nonce)
                        .verifyPresentationIsoMdoc(result.deviceResponse) { documentVerifier() }.getOrThrow()
                        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
                }

                "device retrieval: rejects a request for a missing data element" {
                    it.holder.createDefaultPresentation(
                        request = it.verifier.createPresentationRequest(
                            calcIsoSessionTranscript = simpleTranscriptCallback,
                        ),
                        credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                            isoDeviceRequest("not_in_the_credential")
                        ),
                    ).isFailure shouldBe true
                }

                "device retrieval: preserves repeated document requests" {
                    val request = CredentialPresentationRequest.IsoDeviceRetrieval(
                        DeviceRequest(
                            parsedVersion = Version(1, 0),
                            docRequests = arrayOf(
                                isoDocRequest(CLAIM_GIVEN_NAME),
                                isoDocRequest(CLAIM_DATE_OF_BIRTH),
                            ),
                        )
                    )

                    it.holder.createDefaultPresentation(
                        request = it.verifier.createPresentationRequest(
                            calcIsoSessionTranscript = simpleTranscriptCallback,
                        ),
                        credentialPresentationRequest = request,
                    ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()
                        .deviceResponse.documents.shouldNotBeNull().shouldHaveSize(2)
                }

                "device retrieval: matching keeps all credentials with the same docType" {
                    it.holder.storeCredential(
                        it.issuer.issueCredential(
                            DummyCredentialDataProvider.getCredential(
                                subjectPublicKey = it.holderKeyMaterial.publicKey,
                                credentialScheme = ConstantIndex.AtomicAttribute2023,
                                representation = ISO_MDOC,
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    ).getOrThrow()

                    it.holder.matchPresentationRequestAgainstCredentialStore(
                        CredentialPresentationRequest.IsoDeviceRetrieval(isoDeviceRequest(CLAIM_GIVEN_NAME))
                    ).getOrThrow().shouldBeInstanceOf<IsoDeviceRetrievalMatchingResult<*>>()
                        .matchingResult.documentMatches.shouldBeSingleton().single().shouldHaveSize(2)
                }
            }

            if (mode == IsoRevocationMode.IDENTIFIER_LIST) {
                "identifier list: status info is encoded on issued ISO_MDOC credential" {
                    val issuedCredential = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)

                    issuedCredential.issuedIdentifierListInfo().apply {
                        identifier.isNotEmpty() shouldBe true
                        uri.string shouldContain "/identifier/"
                    }
                }

                "identifier list: identifiers are unique across issued ISO_MDOC credentials" {
                    val first = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)
                        .issuedIdentifierListInfo().identifier
                    val second = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)
                        .issuedIdentifierListInfo().identifier

                    first.contentEquals(second) shouldBe false
                }

                "identifier list: issuing CWT token yields IdentifierList payload" {
                    val statusInfo = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)
                        .issuedIdentifierListInfo()

                    StatusListCwt(
                        value = it.statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                        resolvedAt = null,
                    ).parsedPayload.getOrThrow().apply {
                        revocationList.shouldBeInstanceOf<IdentifierList>()
                        subject shouldBe statusInfo.uri
                    }
                }

                "identifier list: revoking one credential keeps non-revoked credential valid" {
                    val secondHolderKeyMaterial = EphemeralKeyWithSelfSignedCert()
                    val secondHolder = HolderAgent(
                        secondHolderKeyMaterial,
                        InMemorySubjectCredentialStore(),
                        validatorMdoc = ValidatorMdoc(
                            validator = Validator(
                                tokenStatusResolver = identifierListResolver(it.statusListIssuer)
                            )
                        ),
                    ).also { holder ->
                        holder.storeCredential(
                            it.issuer.issueIdentifierListIsoMdoc(secondHolderKeyMaterial.publicKey)
                                .toStoreCredentialInput()
                        ).getOrThrow()
                    }

                    val firstVp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME)
                    val secondRequest = it.verifier.createPresentationRequest(
                        calcIsoSessionTranscript = simpleTranscriptCallback,
                    )
                    val secondVp = PresentedIsoResponse(
                        request = secondRequest,
                        response = createDcqlDeviceResponse(
                            holder = secondHolder,
                            request = secondRequest,
                            attributeNames = arrayOf(CLAIM_GIVEN_NAME),
                        ),
                    )

                    it.revokeSingleStoredCredential() shouldBe true

                    it.verifyPresentation(firstVp).apply {
                        assertPresentedClaims(expectDateOfBirth = false)
                        assertRevocationInvalid(expectedInvalid = true)
                    }

                    it.verifyPresentation(secondVp).apply {
                        assertPresentedClaims(expectDateOfBirth = false)
                        assertRevocationInvalid(expectedInvalid = false)
                    }
                }

                "identifier list: verifier rejects presentation when resolver returns status list token" {
                    val vp = it.createDcqlDeviceResponse(CLAIM_GIVEN_NAME)

                    // no challenge involved here: this verifies the token status of a presentation
                    // that was created for a challenge of another verifier
                    val mismatchedVerifier = VerifierAgent(
                        identifier = it.verifierId,
                        validatorMdoc = ValidatorMdoc(
                            validator = Validator(
                                tokenStatusResolver = statusListResolver(it.statusListIssuer)
                            )
                        ),
                    )

                    mismatchedVerifier.verifyPresentationIsoMdoc(vp.response.deviceResponse, documentVerifier())
                        .getOrThrow()
                        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
                        .documents.shouldBeSingleton().first().freshnessSummary.tokenStatusValidationResult
                        .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
                }
            }
        }
    }
}

private fun isoDeviceRequest(vararg claimNames: String) = DeviceRequest(
    parsedVersion = Version(1, 0),
    docRequests = arrayOf(isoDocRequest(*claimNames)),
)

private fun isoDocRequest(vararg claimNames: String) = DocRequest(
    ByteStringWrapper(
        ItemsRequest(
            docType = ConstantIndex.AtomicAttribute2023.isoDocType,
            namespaces = mapOf(
                ConstantIndex.AtomicAttribute2023.isoNamespace to ItemsRequestList(
                    claimNames.map { SingleItemsRequest(it, false) }
                )
            ),
        )
    )
)

private enum class IsoRevocationMode(
    val revocationKind: RevocationList.Kind,
    val testNameSuffix: String,
) {
    STATUS_LIST(
        revocationKind = RevocationList.Kind.STATUS_LIST,
        testNameSuffix = "",
    ),
    IDENTIFIER_LIST(
        revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
        testNameSuffix = " with identifier list revocation",
    ),
}

private data class IsoMdocFixture(
    val mode: IsoRevocationMode,
    val holderCredentialStore: InMemorySubjectCredentialStore,
    val holderKeyMaterial: KeyMaterial,
    val issuer: IssuerAgent,
    val statusListIssuer: StatusListAgent,
    val holder: HolderAgent,
    val verifier: NonceChallengeVerifier,
    val verifierId: String,
)

private suspend fun createIsoMdocFixture(mode: IsoRevocationMode): IsoMdocFixture {
    val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
    val issuerCredentialStore = InMemoryIssuerCredentialStore()
    val holderCredentialStore = InMemorySubjectCredentialStore()
    val issuer = IssuerAgent(
        keyMaterial = EphemeralKeyWithSelfSignedCert(),
        issuerCredentialStore = issuerCredentialStore,
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default
    )
    val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
    val validator = ValidatorMdoc(
        validator = Validator(
            tokenStatusResolver = when (mode) {
                IsoRevocationMode.STATUS_LIST -> randomCwtOrJwtResolver(statusListIssuer)
                IsoRevocationMode.IDENTIFIER_LIST -> identifierListResolver(statusListIssuer)
            }
        )
    )
    val holder = HolderAgent(
        holderKeyMaterial,
        holderCredentialStore,
        validatorMdoc = validator,
    ).also {
        issueAndStoreIsoMdoc(it, holderKeyMaterial, issuer, mode.revocationKind)
    }
    val verifierId = "urn:${uuid4()}"

    return IsoMdocFixture(
        mode = mode,
        holderCredentialStore = holderCredentialStore,
        holderKeyMaterial = holderKeyMaterial,
        issuer = issuer,
        statusListIssuer = statusListIssuer,
        holder = holder,
        verifier = NonceChallengeVerifier(
            verifierId = verifierId,
            verifier = VerifierAgent(identifier = verifierId, validatorMdoc = validator),
        ),
        verifierId = verifierId,
    )
}

private fun identifierListResolver(statusListIssuer: StatusListAgent) = TokenStatusResolverImpl(
    resolveStatusListToken = { _ ->
        StatusListCwt(
            value = statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
            resolvedAt = null,
        )
    }
)

private fun statusListResolver(statusListIssuer: StatusListAgent) = TokenStatusResolverImpl(
    resolveStatusListToken = { _ ->
        StatusListCwt(
            value = statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.STATUS_LIST),
            resolvedAt = null,
        )
    }
)

/** A device response together with the request it answers, so that its challenge can be consumed. */
private data class PresentedIsoResponse(
    val request: PresentationRequestParameters,
    val response: CreatePresentationResult.DeviceResponse,
)

private suspend fun IsoMdocFixture.createDcqlDeviceResponse(vararg attributeNames: String) =
    verifier.createPresentationRequest(calcIsoSessionTranscript = simpleTranscriptCallback).let { request ->
        PresentedIsoResponse(
            request = request,
            response = createDcqlDeviceResponse(
                holder = holder,
                request = request,
                attributeNames = attributeNames,
            ),
        )
    }

private suspend fun IsoMdocFixture.verifyPresentation(presented: PresentedIsoResponse) =
    verifier.consumeChallenge(presented.request.nonce)
        .verifyPresentationIsoMdoc(presented.response.deviceResponse) { documentVerifier() }.getOrThrow()
        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()

private suspend fun IsoMdocFixture.revokeSingleStoredCredential(): Boolean {
    val storeEntry = holderCredentialStore.getCredentials().getOrThrow()
        .filterIsInstance<SubjectCredentialStore.StoreEntry.Iso>()
        .shouldBeSingleton().single()

    return when (mode) {
        IsoRevocationMode.STATUS_LIST -> statusListIssuer.revokeCredentialByIndex(
            FixedTimePeriodProvider.timePeriod,
            storeEntry.mdocStatusListIndex(),
        )

        IsoRevocationMode.IDENTIFIER_LIST -> statusListIssuer.revokeCredentialByIdentifier(
            FixedTimePeriodProvider.timePeriod,
            storeEntry.mdocIdentifierListInfo().identifier,
        )
    }
}

private suspend fun createDcqlDeviceResponse(
    holder: HolderAgent,
    request: PresentationRequestParameters,
    attributeNames: Array<out String>,
): CreatePresentationResult.DeviceResponse {
    val claimsQueries = attributeNames.map {
        DCQLIsoMdocClaimsQuery(
            path = DCQLClaimsPathPointer(
                ConstantIndex.AtomicAttribute2023.isoNamespace,
                it
            )
        )
    }.toTypedArray()

    val presentationParameters = holder.createDefaultPresentation(
        request = request,
        credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
            buildDCQLQuery(*claimsQueries)
        )
    ).getOrThrow() as PresentationResponseParameters.DCQLParameters

    return presentationParameters.verifiablePresentations.values.shouldBeSingleton().firstOrNull()?.first()
        .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
}

private fun Verifier.VerifyPresentationResult.SuccessIso.assertPresentedClaims(expectDateOfBirth: Boolean) {
    documents.shouldBeSingleton().first().apply {
        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
            .shouldNotBeNull().elementValue shouldBe "Susanne"

        if (expectDateOfBirth) {
            validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_DATE_OF_BIRTH }
                .shouldNotBeNull().elementValue shouldBe LocalDate(1990, 1, 1)
        }
    }
}

private fun Verifier.VerifyPresentationResult.SuccessIso.assertRevocationInvalid(expectedInvalid: Boolean) {
    val tokenStatusValidationResult = documents.shouldBeSingleton().first().freshnessSummary.tokenStatusValidationResult
    if (expectedInvalid) {
        tokenStatusValidationResult.shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
    } else {
        tokenStatusValidationResult.shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
    }
}
// Simple Session Transcript (mostly empty)
private val simpleTranscriptCallback: () -> SessionTranscript = {
    SessionTranscript.forQr(
        deviceEngagementBytes = byteArrayOf(),
        eReaderKeyBytes = byteArrayOf(),
    )
}

private fun SubjectCredentialStore.StoreEntry.Iso.mdocStatusListIndex(): ULong =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<StatusListInfo>().index

private fun Issuer.IssuedCredential.Iso.issuedIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

private fun SubjectCredentialStore.StoreEntry.Iso.mdocIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

private suspend fun IssuerAgent.issueIdentifierListIsoMdoc(subjectPublicKey: CryptoPublicKey) = issueCredential(
    DummyCredentialDataProvider.getCredential(
        subjectPublicKey = subjectPublicKey,
        credentialScheme = ConstantIndex.AtomicAttribute2023,
        representation = ISO_MDOC,
        revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
    ).getOrThrow()
).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

// No OpenID4VP, no need to verify the device signature
private fun documentVerifier(): suspend (MobileSecurityObject, Document) -> Boolean = { _, _ -> true }

private fun buildDCQLQuery(vararg claimsQueries: DCQLIsoMdocClaimsQuery) = DCQLQuery(
    credentials = DCQLCredentialQueryList(
        DCQLIsoMdocCredentialQuery(
            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
            format = CredentialFormatEnum.MSO_MDOC,
            claims = DCQLClaimsQueryList(
                claimsQueries.toList().toNonEmptyList(),
            ),
            meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = ConstantIndex.AtomicAttribute2023.isoDocType,
            )
        )
    )
)
