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
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
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


val AgentIsoIdentifierMdocTest by testSuite {

    withFixtureGenerator(suspend {
        val holderCredentialStore = InMemorySubjectCredentialStore()
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val issuer = IssuerAgent(
            keyMaterial = EphemeralKeyWithSelfSignedCert(),
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val tokenStatusResolver = TokenStatusResolverImpl(
            resolveStatusListToken = { _ ->
                StatusListCwt(
                    value = statusListIssuer.issueStatusListCwt(kind = RevocationList.Kind.IDENTIFIER_LIST),
                    resolvedAt = null,
                )
            }
        )
        val validator = ValidatorMdoc(
            validator = Validator(tokenStatusResolver = tokenStatusResolver)
        )
        val holder = HolderAgent(
            keyMaterial = holderKeyMaterial,
            subjectCredentialStore = holderCredentialStore,
            validatorMdoc = validator,
        ).also {
            it.storeCredential(
                issuer.issueIdentifierListIsoMdoc(holderKeyMaterial.publicKey).toStoreCredentialInput()
            ).getOrThrow()
        }
        val verifierId = "urn:${uuid4()}"
        object {
            val challenge = uuid4().toString()
            val holderKeyMaterial = holderKeyMaterial
            val holderCredentialStore = holderCredentialStore
            val holder = holder
            val issuer = issuer
            val statusListIssuer = statusListIssuer
            val verifier = VerifierAgent(identifier = verifierId, validatorMdoc = validator)
            val verifierId = verifierId
            val signer = SignCose<ByteArray>(keyMaterial = holderKeyMaterial)
        }
    }) - {
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

        "presex: simple walk-through success with identifier list revocation" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId,
                    calcIsoDeviceSignaturePlain = simpleSigner(it.signer),
                ),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.shouldBeSingleton().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()

            it.verifier.verifyPresentationIsoMdoc(vp.deviceResponse, documentVerifier())
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().apply {
                    documents.shouldBeSingleton().first().apply {
                        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                            .shouldNotBeNull().elementValue shouldBe "Susanne"
                        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_DATE_OF_BIRTH }
                            .shouldNotBeNull().elementValue shouldBe LocalDate(1990, 1, 1)
                        freshnessSummary.tokenStatusValidationResult
                            .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                    }
                }
        }

        "presex: revoked credential with identifier list revocation" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId,
                    calcIsoDeviceSignaturePlain = simpleSigner(it.signer),
                ),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME),
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.shouldBeSingleton().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()

            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Iso>()
                .shouldBeSingleton().single()
                .apply {
                    it.statusListIssuer.revokeCredentialByIdentifier(
                        FixedTimePeriodProvider.timePeriod,
                        mdocIdentifierListInfo().identifier,
                    ) shouldBe true
                }

            it.verifier.verifyPresentationIsoMdoc(vp.deviceResponse, documentVerifier())
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().apply {
                    documents.shouldBeSingleton().first().apply {
                        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                            .shouldNotBeNull().elementValue shouldBe "Susanne"
                        freshnessSummary.tokenStatusValidationResult
                            .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
                    }
                }
        }

        "dcql: simple walk-through success with identifier list revocation" {
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId,
                    calcIsoDeviceSignaturePlain = simpleSigner(it.signer),
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLIsoMdocClaimsQuery(
                            namespace = ConstantIndex.AtomicAttribute2023.isoNamespace,
                            claimName = CLAIM_GIVEN_NAME,
                        ),
                        DCQLIsoMdocClaimsQuery(
                            namespace = ConstantIndex.AtomicAttribute2023.isoNamespace,
                            claimName = CLAIM_DATE_OF_BIRTH,
                        ),
                    )
                ),
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.shouldBeSingleton().firstOrNull()?.first()
                .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()

            it.verifier.verifyPresentationIsoMdoc(vp.deviceResponse, documentVerifier())
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().apply {
                    documents.shouldBeSingleton().first().apply {
                        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                            .shouldNotBeNull().elementValue shouldBe "Susanne"
                        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_DATE_OF_BIRTH }
                            .shouldNotBeNull().elementValue shouldBe LocalDate(1990, 1, 1)
                        freshnessSummary.tokenStatusValidationResult
                            .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                    }
                }
        }

        "dcql: revoked credential with identifier list revocation" {
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = it.challenge,
                    audience = it.verifierId,
                    calcIsoDeviceSignaturePlain = simpleSigner(it.signer),
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLIsoMdocClaimsQuery(
                            namespace = ConstantIndex.AtomicAttribute2023.isoNamespace,
                            claimName = CLAIM_GIVEN_NAME,
                        ),
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.shouldBeSingleton().firstOrNull()?.first()
                .shouldBeInstanceOf<CreatePresentationResult.DeviceResponse>()

            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.Iso>()
                .shouldBeSingleton().single()
                .apply {
                    it.statusListIssuer.revokeCredentialByIdentifier(
                        FixedTimePeriodProvider.timePeriod,
                        mdocIdentifierListInfo().identifier,
                    ) shouldBe true
                }

            it.verifier.verifyPresentationIsoMdoc(vp.deviceResponse, documentVerifier())
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessIso>().apply {
                    documents.shouldBeSingleton().first().apply {
                        validItems.firstOrNull { item -> item.elementIdentifier == CLAIM_GIVEN_NAME }
                            .shouldNotBeNull().elementValue shouldBe "Susanne"
                        freshnessSummary.tokenStatusValidationResult
                            .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
                    }
                }
        }
    }
}

private fun Issuer.IssuedCredential.Iso.issuedIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

private fun SubjectCredentialStore.StoreEntry.Iso.mdocIdentifierListInfo(): IdentifierListInfo =
    issuerSigned.issuerAuth.payload.shouldNotBeNull().status.shouldNotBeNull().shouldBeInstanceOf<IdentifierListInfo>()

private suspend fun IssuerAgent.issueIdentifierListIsoMdoc(subjectPublicKey: CryptoPublicKey) =
    issueCredential(
        DummyCredentialDataProvider.getCredential(
            subjectPublicKey = subjectPublicKey,
            credentialScheme = ConstantIndex.AtomicAttribute2023,
            representation = ConstantIndex.CredentialRepresentation.ISO_MDOC,
            revocationKind = RevocationList.Kind.IDENTIFIER_LIST,
        ).getOrThrow()
    ).getOrThrow().shouldBeInstanceOf<Issuer.IssuedCredential.Iso>()

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
