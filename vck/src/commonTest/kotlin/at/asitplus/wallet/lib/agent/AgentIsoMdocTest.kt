package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.iso.Document
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
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
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.cbor.SignCose
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.PresentationExchangeRequest
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeSingleton
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.datetime.LocalDate
import kotlinx.serialization.builtins.ByteArraySerializer

val AgentIsoMdocTest by testSuite {

    for (mode in IsoRevocationMode.entries) {
        withFixtureGenerator(suspend { createIsoMdocFixture(mode) }) - {
            "presex: simple walk-through success${mode.testNameSuffix}" {
                val vp = it.createPresexDeviceResponse(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)

                it.verifyPresentation(vp).apply {
                    assertPresentedClaims(expectDateOfBirth = true)
                    assertRevocationInvalid(expectedInvalid = false)
                }
            }

            "presex: revoked credential${mode.testNameSuffix}" {
                val vp = it.createPresexDeviceResponse(CLAIM_GIVEN_NAME)

                it.revokeSingleStoredCredential() shouldBe true

                it.verifyPresentation(vp).apply {
                    assertPresentedClaims(expectDateOfBirth = false)
                    assertRevocationInvalid(expectedInvalid = true)
                }
            }

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

            if (mode == IsoRevocationMode.IDENTIFIER_LIST) {
                "identifier list: status info is encoded on issued ISO_MDOC credential" {
                    val issuedCredential = it.issuer.issueIdentifierListIsoMdoc(it.holderKeyMaterial.publicKey)

                    val statusInfo = issuedCredential.issuedIdentifierListInfo()
                    statusInfo.identifier.isNotEmpty() shouldBe true
                    statusInfo.uri.string shouldContain "/identifier/"
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

                    val payload = StatusListCwt(
                        value = it.statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                        resolvedAt = null,
                    ).parsedPayload.getOrThrow()

                    payload.revocationList.shouldBeInstanceOf<IdentifierList>()
                    payload.subject shouldBe statusInfo.uri
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

                    val firstVp = it.createPresexDeviceResponse(CLAIM_GIVEN_NAME)
                    val secondVp = createPresexDeviceResponse(
                        holder = secondHolder,
                        challenge = it.challenge,
                        verifierId = it.verifierId,
                        signer = SignCose(keyMaterial = secondHolderKeyMaterial),
                        attributeNames = arrayOf(CLAIM_GIVEN_NAME),
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
                    val vp = it.createPresexDeviceResponse(CLAIM_GIVEN_NAME)

                    val mismatchedVerifier = VerifierAgent(
                        identifier = it.verifierId,
                        validatorMdoc = ValidatorMdoc(
                            validator = Validator(
                                tokenStatusResolver = statusListResolver(it.statusListIssuer)
                            )
                        ),
                    )

                    mismatchedVerifier.verifyPresentationIsoMdoc(vp.deviceResponse, documentVerifier()).getOrThrow()
                        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>()
                        .documents.shouldBeSingleton().first().freshnessSummary.tokenStatusValidationResult
                        .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
                }
            }
        }
    }
}

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
    val verifier: VerifierAgent,
    val verifierId: String,
    val challenge: String,
    val signer: SignCose<ByteArray>,
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
        it.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    subjectPublicKey = holderKeyMaterial.publicKey,
                    credentialScheme = ConstantIndex.AtomicAttribute2023,
                    representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
                    revocationKind = mode.revocationKind,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
    }
    val verifierId = "urn:${uuid4()}"

    return IsoMdocFixture(
        mode = mode,
        holderCredentialStore = holderCredentialStore,
        holderKeyMaterial = holderKeyMaterial,
        issuer = issuer,
        statusListIssuer = statusListIssuer,
        holder = holder,
        verifier = VerifierAgent(identifier = verifierId, validatorMdoc = validator),
        verifierId = verifierId,
        challenge = uuid4().toString(),
        signer = SignCose(keyMaterial = holderKeyMaterial),
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

private suspend fun IsoMdocFixture.createPresexDeviceResponse(vararg attributeNames: String) =
    createPresexDeviceResponse(
        holder = holder,
        challenge = challenge,
        verifierId = verifierId,
        signer = signer,
        attributeNames = attributeNames,
    )

private suspend fun IsoMdocFixture.createDcqlDeviceResponse(vararg attributeNames: String) = createDcqlDeviceResponse(
    holder = holder,
    challenge = challenge,
    verifierId = verifierId,
    signer = signer,
    attributeNames = attributeNames,
)

private suspend fun IsoMdocFixture.verifyPresentation(deviceResponse: CreatePresentationResult.DeviceResponse) =
    verifier.verifyPresentationIsoMdoc(deviceResponse.deviceResponse, documentVerifier()).getOrThrow()
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

private suspend fun createPresexDeviceResponse(
    holder: HolderAgent,
    challenge: String,
    verifierId: String,
    signer: SignCose<ByteArray>,
    attributeNames: Array<out String>,
): CreatePresentationResult.DeviceResponse {
    val presentationParameters = holder.createPresentation(
        request = PresentationRequestParameters(
            nonce = challenge,
            audience = verifierId,
            calcIsoDeviceSignaturePlain = simpleSigner(signer)
        ),
        credentialPresentation = buildPresentationDefinition(*attributeNames)
    ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

    return presentationParameters.presentationResults.shouldBeSingleton().firstOrNull()
        .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()
}

private suspend fun createDcqlDeviceResponse(
    holder: HolderAgent,
    challenge: String,
    verifierId: String,
    signer: SignCose<ByteArray>,
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
        request = PresentationRequestParameters(
            nonce = challenge,
            audience = verifierId,
            calcIsoDeviceSignaturePlain = simpleSigner(signer)
        ),
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

private fun simpleSigner(
    signer: SignCose<ByteArray>
): suspend (IsoDeviceSignatureInput) -> CoseSigned<ByteArray>? = { input ->
    signer(
        protectedHeader = null,
        unprotectedHeader = null,
        payload = input.docType.encodeToByteArray(),
        serializer = ByteArraySerializer()
    ).getOrThrow()
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
        representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
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

private fun buildPresentationDefinition(vararg attributeName: String) = PresentationExchangePresentation(
    PresentationExchangeRequest(
        PresentationDefinition(
            DifInputDescriptor(
                id = ConstantIndex.AtomicAttribute2023.isoDocType,
                constraints = Constraint(
                    fields = attributeName.map {
                        ConstraintField(
                            path = listOf(
                                NormalizedJsonPath(
                                    NameSegment(ConstantIndex.AtomicAttribute2023.isoNamespace),
                                    NameSegment(it),
                                ).toString()
                            )
                        )
                    }.toSet()
                )
            )
        ),
    )
)