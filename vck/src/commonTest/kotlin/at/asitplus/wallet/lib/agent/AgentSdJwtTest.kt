package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
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
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withFixtureGenerator
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.StatusListCwt
import at.asitplus.wallet.lib.data.StatusListJwt
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.communication.primitives.StatusListTokenMediaType
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.extensions.sdHashInput
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsHeaderIdentifierFun
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.randomCwtOrJwtResolver
import at.asitplus.wallet.lib.jws.VerifyStatusListTokenHAIP
import com.benasher44.uuid.uuid4
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldNotBeInstanceOf
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock


val AgentSdJwtTest by testSuite {

    withFixtureGenerator(suspend {
        val issuerCredentialStore = InMemoryIssuerCredentialStore()
        val holderCredentialStore = InMemorySubjectCredentialStore()
        val issuer = IssuerAgent(
            issuerCredentialStore = issuerCredentialStore,
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        )
        val holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        val statusListIssuer = StatusListAgent(issuerCredentialStore = issuerCredentialStore)

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
                    ).getOrThrow()
                ).getOrThrow().toStoreCredentialInput()
            ).getOrThrow()
        }
        object {
            val holder = holder
            val holderCredentialStore = holderCredentialStore
            val holderKeyMaterial = holderKeyMaterial
            val statusListIssuer = statusListIssuer
            val verifierId = "urn:${uuid4()}"
            val verifier = VerifierAgent(
                identifier = verifierId,
                validatorSdJwt = validator,
            )
            val challenge = uuid4().toString()
        }
    }) - {

        "keyBindingJws contains more JWK attributes, still verifies" {
            val credential = it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first()
            val sdJwt = createSdJwtPresentation(
                signKeyBindingJws = SignJwt(it.holderKeyMaterial, { header, _ ->
                    header.copy(keyId = "definitely not matching")
                }),
                audienceId = it.verifierId,
                challenge = it.challenge,
                validSdJwtCredential = credential,
                claimName = CLAIM_GIVEN_NAME
            )
            it.verifier.verifyPresentationSdJwt(sdJwt.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject.keys shouldContain CLAIM_GIVEN_NAME
                    freshnessSummary.tokenStatusValidationResult
                        .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
        }

        "presex: simple walk-through success" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
                    reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
                    freshnessSummary.tokenStatusValidationResult
                        .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
        }

        "presex: wrong key binding jwt" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
            // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
            val freshKbJwt = createFreshSdJwtKeyBinding(it.challenge, it.verifierId)
            val malformedVpSdJwt = vp.serialized.replaceAfterLast("~", freshKbJwt.substringAfterLast("~"))

            it.verifier.verifyPresentationSdJwt(SdJwtSigned.parseCatching(malformedVpSdJwt).getOrThrow(), it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "presex: wrong challenge in key binding jwt" {
            val malformedChallenge = it.challenge.reversed()
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(malformedChallenge, it.verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "presex: revoked sd jwt" {
            val presentationParameters = it.holder.createPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .forEach { storeEntry ->
                    it.statusListIssuer.revokeCredential(
                        FixedTimePeriodProvider.timePeriod,
                        storeEntry.sdJwt.credentialStatus.shouldNotBeNull().statusList.shouldNotBeNull().index
                    ) shouldBe true
                }
            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
        }

        "dcql: simple walk-through success" {
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
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

            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>().apply {
                    reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
                    reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
                    freshnessSummary.tokenStatusValidationResult
                        .shouldNotBeInstanceOf<TokenStatusValidationResult.Invalid>()
                }
        }

        "dcql: wrong key binding jwt" {
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                ),
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
            // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
            val freshKbJwt = createFreshSdJwtKeyBinding(it.challenge, it.verifierId)
            val malformedVpSdJwt = vp.serialized.replaceAfterLast("~", freshKbJwt.substringAfterLast("~"))

            it.verifier.verifyPresentationSdJwt(SdJwtSigned.parseCatching(malformedVpSdJwt).getOrThrow(), it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "dcql: wrong challenge in key binding jwt" {
            val malformedChallenge = it.challenge.reversed()
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

            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "dcql: revoked sd jwt" {
            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            it.holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .forEach { storeEntry ->
                    it.statusListIssuer.revokeCredential(
                        FixedTimePeriodProvider.timePeriod,
                        storeEntry.sdJwt.credentialStatus.shouldNotBeNull().statusList.shouldNotBeNull().index,
                    ) shouldBe true
                }
            it.verifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Invalid>()
        }

        "sd-jwt vc request verified with HAIP status list rules" {
            val haipTokenStatusResolver = TokenStatusResolverImpl(
                resolveStatusListToken = { _ ->
                    it.statusListIssuer.provideStatusListToken(
                        listOf(StatusListTokenMediaType.Jwt),
                        Clock.System.now(),
                    ).second
                },
                verifyJwsObjectIntegrity = VerifyStatusListTokenHAIP(),
            )

            val haipVerifier = VerifierAgent(
                identifier = it.verifierId,
                validatorSdJwt = ValidatorSdJwt(
                    validator = Validator(tokenStatusResolver = haipTokenStatusResolver),
                ),
            )

            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.first()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            haipVerifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Valid>()
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

            val haipVerifier = VerifierAgent(
                identifier = it.verifierId,
                validatorSdJwt = ValidatorSdJwt(
                    validator = Validator(tokenStatusResolver = haipTokenStatusResolver),
                ),
            )

            val presentationParameters = it.holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = it.challenge, audience = it.verifierId),
                credentialPresentationRequest = CredentialPresentationRequest.DCQLRequest(
                    buildDCQLQuery(
                        DCQLJsonClaimsQuery(
                            path = DCQLClaimsPathPointer(CLAIM_GIVEN_NAME),
                        )
                    ),
                )
            ).getOrThrow() as PresentationResponseParameters.DCQLParameters

            val vp = presentationParameters.verifiablePresentations.values.first()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val test = haipVerifier.verifyPresentationSdJwt(vp.sdJwt, it.challenge)

            test.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
                .freshnessSummary.tokenStatusValidationResult
                .shouldBeInstanceOf<TokenStatusValidationResult.Rejected>()
        }
    }
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

private fun buildPresentationDefinition(vararg attributeName: String) = PresentationExchangePresentation(
    CredentialPresentationRequest.PresentationExchangeRequest
        .forAttributeNames(*attributeName.map { "$['$it']" }.toTypedArray())
)

suspend fun createFreshSdJwtKeyBinding(challenge: String, verifierId: String): String {
    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val holder = HolderAgent(holderKeyMaterial)
    holder.storeCredential(
        IssuerAgent(
            identifier = "https://issuer.example.com/".toUri(),
            randomSource = RandomSource.Default
        ).issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                SD_JWT,
            ).getOrThrow()
        ).getOrThrow().toStoreCredentialInput()
    )
    val presentationResult = holder.createPresentation(
        request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
        credentialPresentation = PresentationExchangePresentation(
            CredentialPresentationRequest.PresentationExchangeRequest(
                PresentationDefinition(
                    DifInputDescriptor(id = uuid4().toString())
                ),
            ),
        )
    ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()
    return (presentationResult.presentationResults.first() as CreatePresentationResult.SdJwt).serialized
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
    val jwsFromIssuer = JwsSigned.deserialize(JsonObject.serializer(), sdJwtSerialized).getOrElse {
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
): JwsSigned<KeyBindingJws> = signKeyBindingJws(
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
