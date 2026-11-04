package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.ClaimDescription
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import com.benasher44.uuid.uuid4
import io.github.z4kn4fein.semver.Version
import io.kotest.engine.runBlocking
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val AgentIsoMdocMultipleDocumentsTest by matrixSuite {

    fixture {
        object {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val issuer = IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            val validator = statusCheckingValidator(statusListIssuer)
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val holder = HolderAgent(keyMaterial = holderKeyMaterial).also {
                runBlocking {
                    it.storeCredential(
                        issuer.issueCredential(
                            DummyCredentialDataProvider.getCredentialForClaim(
                                holderKeyMaterial.publicKey,
                                AtomicAttribute2023,
                                ISO_MDOC,
                                ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    ).getOrThrow()
                    it.storeCredential(
                        issuer.issueCredential(
                            DummyCredentialDataProvider.getCredentialForClaim(
                                holderKeyMaterial.publicKey,
                                AtomicAttribute2025,
                                ISO_MDOC,
                                ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
                            ).getOrThrow()
                        ).getOrThrow().toStoreCredentialInput()
                    ).getOrThrow()
                }
            }
            val verifierId = "urn:${uuid4()}"
            val verifier = NonceChallengeVerifier(verifierId = verifierId)
        }
    } - {

        test("dcql: multiple credentials should be multiple device responses for remote presentation") { scope ->
            val request = scope.verifier.createPresentationRequest(
                calcIsoSessionTranscript = simpleTranscriptCallback
            )
            val presentationRequest = CredentialPresentationRequest.DCQLRequest(
                DCQLQuery(
                    credentials = DCQLCredentialQueryList(
                        isoMdocCredentialQuery(AtomicAttribute2023, CLAIM_GIVEN_NAME),
                        isoMdocCredentialQuery(AtomicAttribute2025, CLAIM_FAMILY_NAME),
                    )
                )
            )
            scope.holder.matchPresentationRequestAgainstCredentialStore(presentationRequest).getOrThrow()
                .shouldBeInstanceOf<DCQLMatchingResult<*>>()
            val presentationParameters = scope.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = presentationRequest,
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()

            val presentationResults = presentationParameters.verifiablePresentations.values.flatten()
            // all presentations of this response answer the single challenge of the request above,
            // so it is consumed once, and not per presentation
            val context = scope.verifier.consumeChallenge(request.nonce).context(
                audience = scope.verifierId,
                sessionTranscript = simpleTranscriptCallback(),
            )
            presentationResults.shouldHaveSize(2).map { result ->
                result.shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
                scope.validator.validatePresentation(result, context, statusCheckingPolicy).shouldBeSingleton().first()
                    .apply { observedStatus shouldBe TokenStatus.Valid }
                    .acceptedOrThrow()
            }.flatMap { it.issuerSignedItems() }.apply {
                    firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                        .shouldNotBeNull().elementValue shouldBe "Susanne"
                    firstOrNull { item -> item.elementIdentifier == CLAIM_FAMILY_NAME }
                        .shouldNotBeNull().elementValue shouldBe "Meier"
                }
        }

        test("device retrieval: multiple document requests produce one device response") {
            val request = it.verifier.createPresentationRequest(
                calcIsoSessionTranscript = simpleTranscriptCallback,
            )
            val result = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.IsoDeviceRetrieval(
                    DeviceRequest(
                        parsedVersion = Version(1, 0),
                        docRequests = arrayOf(
                            docRequest(AtomicAttribute2023, CLAIM_GIVEN_NAME),
                            docRequest(AtomicAttribute2025, CLAIM_FAMILY_NAME),
                        ),
                    )
                ),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DeviceRetrievalParameters>()

            it.validator.validatePresentation(
                presentation = CreatePresentationResult.DeviceResponse(result.deviceResponse),
                context = it.verifier.consumeChallenge(request.nonce).context(
                    audience = it.verifierId,
                    sessionTranscript = simpleTranscriptCallback(),
                ),
                policy = statusCheckingPolicy,
            ).shouldHaveSize(2).flatMap { it.acceptedOrThrow().issuerSignedItems() }.apply {
                    first { it.elementIdentifier == CLAIM_GIVEN_NAME }.elementValue shouldBe "Susanne"
                    first { it.elementIdentifier == CLAIM_FAMILY_NAME }.elementValue shouldBe "Meier"
                }
        }
    }
}

private fun docRequest(scheme: IsoMdocCredentialScheme, claim: String) = DocRequest(
    itemsRequest = ByteStringWrapper(
        ItemsRequest(
            docType = scheme.isoDocType,
            namespaces = mapOf(
                scheme.isoNamespace to ItemsRequestList(listOf(SingleItemsRequest(claim, false)))
            ),
        )
    )
)

private fun isoMdocCredentialQuery(
    scheme: CredentialScheme,
    claim: String,
) = DCQLIsoMdocCredentialQuery(
    id = DCQLCredentialQueryIdentifier(uuid4().toString()),
    meta = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
        doctypeValue = scheme.isoDocType!!,
    ),
    claims = DCQLClaimsQueryList(
        nonEmptyListOf(
            DCQLIsoMdocClaimsQuery(
                path = DCQLClaimsPathPointer(scheme.isoNamespace!!, claim)
            )
        )
    ),
)

// Simple Session Transcript (mostly empty)
private val simpleTranscriptCallback: () -> SessionTranscript = {
    SessionTranscript.Qr(
        deviceEngagementBytes = byteArrayOf(),
        eReaderKeyBytes = byteArrayOf(),
    )
}

private fun ValidatedPresentation.issuerSignedItems() = shouldBeInstanceOf<ValidatedPresentation.MdocDocument>()
    .credential.issuerSigned.namespaces.shouldNotBeNull().values.flatMap { list -> list.entries.map { it.value } }


object AtomicAttribute2025 : CredentialScheme, IsoMdocCredentialScheme, SdJwtCredentialScheme, VcJwtCredentialScheme {
    const val CLAIM_GIVEN_NAME = "given_name"
    const val CLAIM_FAMILY_NAME = "family_name"
    const val CLAIM_DATE_OF_BIRTH = "date_of_birth"
    const val CLAIM_PORTRAIT = "portrait"
    override val vcType: String = "AtomicAttribute2025"
    override val sdJwtType: String = "AtomicAttribute2025"
    override val isoNamespace: String = "at.a-sit.wallet.atomic-attribute-2025"
    override val isoDocType: String = "at.a-sit.wallet.atomic-attribute-2025.iso"
    override val claimDescriptions: Set<ClaimDescription>
        get() = setOf(
            ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_GIVEN_NAME)),
            ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_FAMILY_NAME)),
            ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_DATE_OF_BIRTH)),
            ClaimDescription(OpenId4VciClaimsPathPointer(CLAIM_PORTRAIT)),
        )
    override val supportedRepresentations: Collection<at.asitplus.wallet.lib.data.CredentialRepresentation>
        get() = listOf(ISO_MDOC, PLAIN_JWT, SD_JWT)
}
