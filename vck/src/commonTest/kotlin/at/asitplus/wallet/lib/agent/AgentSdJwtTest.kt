package at.asitplus.wallet.lib.agent

import at.asitplus.catching
import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.iso.sha256
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsQueryList
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLCredentialQueryList
import at.asitplus.openid.dcql.DCQLJsonClaimsQuery
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLSdJwtCredentialMetadataAndValidityConstraints
import at.asitplus.openid.dcql.DCQLSdJwtCredentialQuery
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.testballoon.matrix.fixture
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyStatusListTokenHAIP
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import com.benasher44.uuid.uuid4
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock


val AgentSdJwtTest by matrixSuite {

    fixture {
        runBlocking {
            val issuerCredentialStore = InMemoryIssuerCredentialStore()
            val holderCredentialStore = InMemorySubjectCredentialStore()
            val issuer = IssuerAgent(
                issuerCredentialStore = issuerCredentialStore,
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            )
            val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
            val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)
            // HAIP requires the status list token to be signed by a certificate that is not self-signed
            val statusListCa = TestCertificateAuthority()
            val caSignedStatusListIssuer = StatusListAgent(
                keyMaterial = statusListCa.issue("Test Status List Issuer"),
                issuerCredentialStore = issuerCredentialStore,
            )

            val validator = ValidatorSdJwt(
                validator = Validator(tokenStatusResolver = randomCwtOrJwtResolver(statusListIssuer))
            )
            val holder = HolderAgent(
                holderKeyMaterial,
                holderCredentialStore,
                validatorSdJwt = validator,
            ).also {
                it.storeCredential(
                    issuer.issueCredential(
                        DummyCredentialDataProvider.getCredential(
                            holderKeyMaterial.publicKey,
                            ConstantIndex.AtomicAttribute2023,
                            SD_JWT,
                        ).getOrThrow().shouldBeInstanceOf<CredentialToBeIssued.VcSd>()
                            .copy(sdAlgorithm = Digest.SHA256)
                    ).getOrThrow().toStoreCredentialInput()
                ).getOrThrow()
            }
            object {
                val holder = holder
                val holderCredentialStore = holderCredentialStore
                val holderKeyMaterial = holderKeyMaterial
                val statusListIssuer = statusListIssuer
                val statusListCa = statusListCa
                val caSignedStatusListIssuer = caSignedStatusListIssuer
                val verifierId = "urn:${uuid4()}"
                val verifier = NonceChallengeVerifier(
                    verifierId = verifierId,
                    verifier = VerifierAgent(
                        identifier = verifierId,
                        validatorSdJwt = validator,
                    ),
                )
            }
        }
    } - {

        "keyBindingJws contains more JWK attributes, still verifies" {
            val request = it.verifier.createPresentationRequest()
            val credential = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first()
            val sdJwt = createSdJwtPresentation(
                signKeyBindingJws = SignJwt(it.holderKeyMaterial, { header, _ ->
                    header.copy(keyId = "definitely not matching")
                }),
                audienceId = request.audience,
                challenge = request.nonce,
                validSdJwtCredential = credential,
                claimName = CLAIM_GIVEN_NAME
            )
            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(sdJwt.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject.keys shouldContain CLAIM_GIVEN_NAME
                    freshnessSummary.tokenStatusValidationResult
                        .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
        }

        "dcql: simple walk-through success" {
            val request = it.verifier.createPresentationRequest()
            val presentationParameters = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        ),
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_DATE_OF_BIRTH),
                        ),
                    )
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.flatten().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
                    reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
                    freshnessSummary.tokenStatusValidationResult
                        .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
        }

        "dcql: wrong key binding jwt" {
            val request = it.verifier.createPresentationRequest()
            val presentationParameters = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                ),
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.flatten().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
            // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
            val freshKbJwt = createFreshSdJwtKeyBinding(request.nonce, request.audience)
            val malformedVpSdJwt = vp.serialized.replaceAfterLast("~", freshKbJwt.substringAfterLast("~"))

            shouldThrowAny {
                it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(
                    SdJwtSigned.parseCatching(malformedVpSdJwt).getOrThrow(),
                ).getOrThrow()
            }
        }

        "dcql: wrong challenge in key binding jwt" {
            val request = it.verifier.createPresentationRequest()
            val malformedChallenge = request.nonce.reversed()
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = malformedChallenge,
                    audience = it.verifierId
                ),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.flatten().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            shouldThrowAny {
                it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
            }.message shouldContain "Challenge not correct"
        }

        "dcql: revoked sd jwt" {
            val request = it.verifier.createPresentationRequest()
            val presentationParameters = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.flatten().firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .forEach { storeEntry ->
                    it.statusListIssuer.revokeCredentialByIndex(
                        FixedTimePeriodProvider.timePeriod,
                        storeEntry.sdJwt.statusElement.shouldBeInstanceOf<StatusListInfo>().index,
                    ) shouldBe true
                }
            it.verifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
        }

        "sd-jwt vc request verified with HAIP status list rules" {
            val haipTokenStatusResolver = TokenStatusResolverImpl(
                resolveStatusListToken = { _ ->
                    it.caSignedStatusListIssuer.provideStatusListToken(
                        listOf(StatusListTokenMediaType.Jwt),
                        Clock.System.now(),
                    ).second
                },
                verifyJwsObjectIntegrity = VerifyStatusListTokenHAIP(
                    trustedIssuers = { setOf(it.statusListCa.certificate()) },
                ),
            )

            val haipVerifier = NonceChallengeVerifier(
                verifierId = it.verifierId,
                verifier = VerifierAgent(
                    identifier = it.verifierId,
                    validatorSdJwt = ValidatorSdJwt(
                        validator = Validator(tokenStatusResolver = haipTokenStatusResolver),
                    ),
                ),
            )
            val request = haipVerifier.createPresentationRequest()

            val presentationParameters = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.first().first()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            haipVerifier.consumeChallenge(request.nonce).verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Valid>()
        }

        "sd-jwt vc request rejected with HAIP status list rules and an untrusted issuer" {
            val haipTokenStatusResolver = TokenStatusResolverImpl(
                resolveStatusListToken = { _ ->
                    it.caSignedStatusListIssuer.provideStatusListToken(
                        listOf(StatusListTokenMediaType.Jwt),
                        Clock.System.now(),
                    ).second
                },
                verifyJwsObjectIntegrity = VerifyStatusListTokenHAIP(
                    trustedIssuers = { setOf(TestCertificateAuthority().certificate()) },
                ),
            )

            presentAndVerifySdJwt(it.holder, it.verifierId, haipTokenStatusResolver)
                .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
        }

        "sd-jwt vc request rejected with HAIP status list rules and a self-signed status list certificate" {
            val haipTokenStatusResolver = TokenStatusResolverImpl(
                resolveStatusListToken = { _ ->
                    // the default StatusListAgent key is self-signed, which HAIP forbids
                    it.statusListIssuer.provideStatusListToken(
                        listOf(StatusListTokenMediaType.Jwt),
                        Clock.System.now(),
                    ).second
                },
                verifyJwsObjectIntegrity = VerifyStatusListTokenHAIP(),
            )

            presentAndVerifySdJwt(it.holder, it.verifierId, haipTokenStatusResolver)
                .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
        }

        "sd-jwt vc request rejected without HAIP status list certificate chain" {
            val certStatusKey = EphemeralKeyWithoutCert()
            val noCertStatusListIssuer = StatusListAgent(
                keyMaterial = certStatusKey,
                signStatusListJwt = SignJwt(
                    certStatusKey,
                    JwsHeaderIdentifierFun { header, _ -> header.copy(certificateChain = null) }),
            )

            val haipTokenStatusResolver = TokenStatusResolverImpl(
                resolveStatusListToken = StatusListTokenResolver {
                    noCertStatusListIssuer.provideStatusListToken(
                        listOf(StatusListTokenMediaType.Jwt),
                        Clock.System.now(),
                    ).second
                },
                verifyJwsObjectIntegrity = VerifyStatusListTokenHAIP(),
            )

            val haipVerifier = NonceChallengeVerifier(
                verifierId = it.verifierId,
                verifier = VerifierAgent(
                    identifier = it.verifierId,
                    validatorSdJwt = ValidatorSdJwt(
                        validator = Validator(tokenStatusResolver = haipTokenStatusResolver),
                    ),
                ),
            )
            val request = haipVerifier.createPresentationRequest()

            val presentationParameters = it.holder.createDefaultPresentation(
                request = request,
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.first().first()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val test = haipVerifier.consumeChallenge(request.nonce)
                .verifyPresentationSdJwt(vp.sdJwt).getOrThrow()

            test.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
        }
    }
}

/** Presents the stored SD-JWT to a verifier using [tokenStatusResolver], and returns the status of the token. */
private suspend fun presentAndVerifySdJwt(
    holder: Holder,
    verifierId: String,
    tokenStatusResolver: TokenStatusResolver,
): TokenStatusValidationResult {
    val verifier = NonceChallengeVerifier(
        verifierId = verifierId,
        verifier = VerifierAgent(
            identifier = verifierId,
            validatorSdJwt = ValidatorSdJwt(
                validator = Validator(tokenStatusResolver = tokenStatusResolver),
            ),
        ),
    )
    val presentationParameters = holder.createDefaultPresentation(
        request = verifier.createPresentationRequest(),
        credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
            buildDCQLQuery(
                DCQLJsonClaimsQuery(path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME)),
            ),
        )
    ).getOrThrow() as PresentationResponseParameters.DCQLParameters
    val vp = presentationParameters.verifiablePresentations.values.first().first()
        .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

    return verifier.verifyPresentationSdJwt(vp.sdJwt).getOrThrow()
        .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        .freshnessSummary.tokenStatusValidationResult
}

private fun buildDCQLQuery(vararg claimsQueries: DCQLJsonClaimsQuery) = DCQLQuery(
    credentials = DCQLCredentialQueryList(
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(
                claimsQueries.toList().toNonEmptyList(),
            ),
            meta = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf(ConstantIndex.AtomicAttribute2023.sdJwtType)
            )
        )
    )
)

suspend fun createFreshSdJwtKeyBinding(challenge: String, verifierId: String): String {
    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val holder = HolderAgent(holderKeyMaterial)
    val issuer = IssuerAgent(
        identifier = "https://issuer.example.com/".toUri(),
        randomSource = RandomSource.Default
    )
    DummyCredentialDataProvider.issueAndStoreSdJwt(holder, holderKeyMaterial, issuer)

    val presentationResult = holder.createDefaultPresentation(
        request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
        credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
            buildDCQLQuery(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                )
            )
        )
    ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.DCQLParameters>()
    return (presentationResult.verifiablePresentations.values.first()
        .first() as CreatePresentationResult.SdJwt).serialized
}

private suspend fun createSdJwtPresentation(
    signKeyBindingJws: SignJwtFun<KeyBindingJws>,
    audienceId: String,
    challenge: String,
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    claimName: String,
): CreatePresentationResult.SdJwt {
    val filteredDisclosures = validSdJwtCredential.disclosures
        .filter { it.value!!.claimName == claimName }.keys
    val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, filteredDisclosures)
    val keyBinding = createKeyBindingJws(signKeyBindingJws, audienceId, challenge, issuerJwtPlusDisclosures)
    val sdJwtSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
    val jwsFromIssuer = catching { JwsCompact(sdJwtSerialized) }.getOrElse {
        throw PresentationException(it)
    }
    val sdJwt = SdJwtSigned.presented(jwsFromIssuer, filteredDisclosures, keyBinding)
    return CreatePresentationResult.SdJwt(sdJwt.serialize(), sdJwt)
}

private suspend fun createKeyBindingJws(
    signKeyBindingJws: SignJwtFun<KeyBindingJws>,
    audienceId: String,
    challenge: String,
    issuerJwtPlusDisclosures: String,
): JwsCompactTyped<KeyBindingJws> = signKeyBindingJws(
    JwsContentTypeConstants.KB_JWT,
    KeyBindingJws(
        issuedAt = Clock.System.now(),
        audience = audienceId,
        challenge = challenge,
        sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
    ),
    KeyBindingJws.serializer(),
).getOrElse {
    throw PresentationException(it)
}
