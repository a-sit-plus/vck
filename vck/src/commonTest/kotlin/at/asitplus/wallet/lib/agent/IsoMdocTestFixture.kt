package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.SessionTranscript
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLIsoMdocClaimsQuery
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLIsoMdocCredentialQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.wallet.lib.agent.DummyCredentialDataProvider.issueAndStoreIsoMdoc
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.PresentationValidationResult
import at.asitplus.wallet.lib.validation.StatusValidator
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import com.benasher44.uuid.uuid4
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.LocalDate

/*
 * The fixture of the ISO mdoc agent tests: a holder with an mdoc of `AtomicAttribute2023`, its issuer revoking by
 * a status list or an identifier list, and a verifier validating its presentations.
 */

internal enum class IsoRevocationMode(
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

internal data class IsoMdocFixture(
    val mode: IsoRevocationMode,
    val holderCredentialStore: InMemorySubjectCredentialStore,
    val holderKeyMaterial: KeyMaterial,
    val issuer: IssuerAgent,
    val statusListIssuer: StatusListAgent,
    val holder: HolderAgent,
    val validator: CredentialValidator,
    val verifier: NonceChallengeVerifier,
    val verifierId: String,
)

internal suspend fun createIsoMdocFixture(mode: IsoRevocationMode): IsoMdocFixture {
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
    val validator = CredentialValidator(
        statusValidator = StatusValidator(
            when (mode) {
                IsoRevocationMode.STATUS_LIST -> randomCwtOrJwtResolver(statusListIssuer)
                IsoRevocationMode.IDENTIFIER_LIST ->
                    StatusListTokenResolver {
                        StatusListCwt(
                            value = statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                            resolvedAt = null,
                        )
                    }
            }
        )
    )
    val holder = HolderAgent(holderKeyMaterial, holderCredentialStore).also {
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
        validator = validator,
        verifier = NonceChallengeVerifier(verifierId = verifierId),
        verifierId = verifierId,
    )
}

/** A device response together with the request it answers, so that its challenge can be consumed. */
internal data class PresentedIsoResponse(
    val request: PresentationRequestParameters,
    val response: CreatePresentationResult.DeviceResponse,
)

internal suspend fun IsoMdocFixture.createDcqlDeviceResponse(vararg attributeNames: String) =
    verifier.createPresentationRequest(calcIsoSessionTranscript = qrSessionTranscript).let { request ->
        PresentedIsoResponse(
            request = request,
            response = createDcqlDeviceResponse(
                holder = holder,
                request = request,
                attributeNames = attributeNames,
            ),
        )
    }

internal suspend fun IsoMdocFixture.verifyPresentation(
    presented: PresentedIsoResponse,
    credentialValidator: CredentialValidator = validator,
) = credentialValidator.validatePresentation(
    presentation = presented.response,
    context = verifier.consumeChallenge(presented.request.nonce).context(
        audience = verifierId,
        sessionTranscript = qrSessionTranscript(),
    ),
    policy = statusCheckingPolicy,
).shouldBeSingleton().first()

internal suspend fun IsoMdocFixture.revokeSingleStoredCredential(): Boolean {
    val storeEntry = holderCredentialStore.getCredentials().getOrThrow()
        .filterIsInstance<SubjectCredentialStore.StoreEntry.Iso>()
        .shouldBeSingleton().single()

    return when (mode) {
        IsoRevocationMode.STATUS_LIST -> statusListIssuer.revokeCredentialByIndex(
            FixedTimePeriodProvider.timePeriod,
            storeEntry.issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull()
                .shouldBeInstanceOf<StatusListInfo>().index,
        )

        IsoRevocationMode.IDENTIFIER_LIST -> statusListIssuer.revokeCredentialByIdentifier(
            FixedTimePeriodProvider.timePeriod,
            storeEntry.issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull()
                .shouldBeInstanceOf<IdentifierListInfo>().identifier,
        )
    }
}

internal suspend fun createDcqlDeviceResponse(
    holder: HolderAgent,
    request: PresentationRequestParameters,
    attributeNames: Array<out String>,
): CreatePresentationResult.DeviceResponse {
    val claimsQueries = attributeNames.map {
        DCQLIsoMdocClaimsQuery(
            path = DCQLClaimsPathPointer(ConstantIndex.AtomicAttribute2023.isoNamespace, it)
        )
    }.toTypedArray()

    val presentationParameters = holder.createDefaultPresentation(
        request = request,
        credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(buildDCQLQuery(*claimsQueries))
    ).getOrThrow() as PresentationResponseParameters.DCQLParameters

    return presentationParameters.verifiablePresentations.values.shouldBeSingleton().firstOrNull()?.first()
        .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
}

/** The document is accepted with a valid status, and discloses the requested claims. */
internal fun PresentationValidationResult.assertPresentedClaims(expectDateOfBirth: Boolean) {
    observedStatus shouldBe TokenStatus.Valid
    val items = acceptedOrThrow().shouldBeInstanceOf<ValidatedPresentation.MdocDocument>()
        .credential.issuerSigned.namespaces.shouldNotBeNull()
        .getValue(ConstantIndex.AtomicAttribute2023.isoNamespace).entries.map { it.value }

    items.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
        .shouldNotBeNull().elementValue shouldBe "Susanne"

    if (expectDateOfBirth) {
        items.firstOrNull { item -> item.elementIdentifier == CLAIM_DATE_OF_BIRTH }
            .shouldNotBeNull().elementValue shouldBe LocalDate(1990, 1, 1)
    }
}

/** A simple, mostly empty session transcript, the same for the holder and the verifier. */
internal val qrSessionTranscript: () -> SessionTranscript = {
    SessionTranscript.Qr(
        deviceEngagementBytes = byteArrayOf(),
        eReaderKeyBytes = byteArrayOf(),
    )
}

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
