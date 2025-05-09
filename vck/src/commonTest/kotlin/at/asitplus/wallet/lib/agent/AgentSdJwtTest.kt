package at.asitplus.wallet.lib.agent

import at.asitplus.data.NonEmptyList.Companion.toNonEmptyList
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.openid.dcql.*
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.CredentialPresentation.PresentationExchangePresentation
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlinx.serialization.json.jsonPrimitive
import kotlin.random.Random


class AgentSdJwtTest : FreeSpec({

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderKeyMaterial: KeyMaterial
    lateinit var challenge: String
    lateinit var verifierId: String

    beforeEach {
        val validator = Validator(
            resolveStatusListToken = {
                if (Random.nextBoolean()) StatusListToken.StatusListJwt(
                    issuer.issueStatusListJwt(),
                    resolvedAt = Clock.System.now()
                ) else {
                    StatusListToken.StatusListCwt(
                        issuer.issueStatusListCwt(),
                        resolvedAt = Clock.System.now(),
                    )
                }
            },
        )
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(
            EphemeralKeyWithoutCert(),
            validator = validator,
            issuerCredentialStore = issuerCredentialStore,
        )
        holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        holder = HolderAgent(
            holderKeyMaterial,
            holderCredentialStore,
            validator = validator,
        )
        verifierId = "urn:${uuid4()}"
        verifier = VerifierAgent(
            identifier = verifierId,
            validator = validator,
        )
        challenge = uuid4().toString()
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        ).getOrThrow()
    }

    "keyBindingJws contains more JWK attributes, still verifies" {
        val credential = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first()
        val sdJwt = createSdJwtPresentation(
            signKeyBindingJws = SignJwt(holderKeyMaterial, { it, keyMaterial ->
                it.copy(keyId = "definitely not matching")
            }),
            audienceId = verifierId,
            challenge = challenge,
            validSdJwtCredential = credential,
            claimName = CLAIM_GIVEN_NAME
        )
        val verified = verifier.verifyPresentationSdJwt(sdJwt.sdJwt!!, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.reconstructedJsonObject.keys shouldContain CLAIM_GIVEN_NAME
        verified.tokenStatus?.getOrNull() shouldNotBe TokenStatus.Invalid
    }

    "when using presentation exchange" - {
        "simple walk-through success" {
            val presentationParameters = holder.createPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

            verified.reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
            verified.reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
            verified.tokenStatus?.getOrNull() shouldNotBe TokenStatus.Invalid
        }

        "wrong key binding jwt" {
            val presentationParameters = holder.createPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()
            // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
            val freshKbJwt = createFreshSdJwtKeyBinding(challenge, verifierId)
            val malformedVpSdJwt = vp.serialized.replaceAfterLast("~", freshKbJwt.substringAfterLast("~"))

            verifier.verifyPresentationSdJwt(SdJwtSigned.parse(malformedVpSdJwt)!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "wrong challenge in key binding jwt" {
            val malformedChallenge = challenge.reversed()
            val presentationParameters = holder.createPresentation(
                request = PresentationRequestParameters(malformedChallenge, verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "revoked sd jwt" {
            val presentationParameters = holder.createPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
                credentialPresentation = buildPresentationDefinition(CLAIM_GIVEN_NAME)
            ).getOrThrow().shouldBeInstanceOf<PresentationResponseParameters.PresentationExchangeParameters>()

            val vp = presentationParameters.presentationResults.firstOrNull()
                .shouldBeInstanceOf<CreatePresentationResult.SdJwt>()

            val listOfJwtId = holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .associate { it.sdJwt.jwtId!! to it.sdJwt.notBefore!! }
            issuer.revokeCredentialsWithId(listOfJwtId) shouldBe true
            val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
            verified.tokenStatus?.getOrNull() shouldBe TokenStatus.Invalid
        }
    }

    "when using dcql" - {
        "simple walk-through success" {
            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
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

            val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

            verified.reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
            verified.reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
            verified.tokenStatus?.getOrNull() shouldNotBe TokenStatus.Invalid
        }

        "wrong key binding jwt" {
            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
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
            val freshKbJwt = createFreshSdJwtKeyBinding(challenge, verifierId)
            val malformedVpSdJwt =
                vp.serialized.replaceAfterLast("~", freshKbJwt.substringAfterLast("~"))

            verifier.verifyPresentationSdJwt(SdJwtSigned.parse(malformedVpSdJwt)!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "wrong challenge in key binding jwt" {
            val malformedChallenge = challenge.reversed()
            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(
                    nonce = malformedChallenge,
                    audience = verifierId
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

            verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.ValidationError>()
        }

        "revoked sd jwt" {
            val presentationParameters = holder.createDefaultPresentation(
                request = PresentationRequestParameters(nonce = challenge, audience = verifierId),
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

            val listOfJwtId = holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .associate { it.sdJwt.jwtId!! to it.sdJwt.notBefore!! }
            issuer.revokeCredentialsWithId(listOfJwtId) shouldBe true
            val verified = verifier.verifyPresentationSdJwt(vp.sdJwt!!, challenge)
                .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
            verified.tokenStatus?.getOrNull() shouldBe TokenStatus.Invalid
        }
    }
})

private fun buildDCQLQuery(vararg claimsQueries: DCQLJsonClaimsQuery) = DCQLQuery(
    credentials = DCQLCredentialQueryList(
        DCQLSdJwtCredentialQuery(
            id = DCQLCredentialQueryIdentifier(uuid4().toString()),
            format = CredentialFormatEnum.DC_SD_JWT,
            claims = DCQLClaimsQueryList(
                claimsQueries.toList().toNonEmptyList(),
            )
        )
    )
)

private fun buildPresentationDefinition(vararg attributeName: String) = PresentationExchangePresentation(
    CredentialPresentationRequest.PresentationExchangeRequest
        .forAttributeNames(*attributeName.map { it -> "$['$it']" }.toTypedArray())
)

suspend fun createFreshSdJwtKeyBinding(challenge: String, verifierId: String): String {
    val holderKeyMaterial = EphemeralKeyWithoutCert()
    val holder = HolderAgent(holderKeyMaterial)
    holder.storeCredential(
        IssuerAgent().issueCredential(
            DummyCredentialDataProvider.getCredential(
                holderKeyMaterial.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
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
    val jwsFromIssuer = JwsSigned.deserialize<VerifiableCredentialSdJwt>(
        VerifiableCredentialSdJwt.serializer(),
        sdJwtSerialized
    ).getOrElse {
        Napier.w("Could not re-create JWS from stored SD-JWT", it)
        throw PresentationException(it)
    }
    val sdJwt = SdJwtSigned.serializePresentation(jwsFromIssuer, filteredDisclosures, keyBinding)
    return CreatePresentationResult.SdJwt(sdJwt)
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
    Napier.w("Could not create JWS for presentation", it)
    throw PresentationException(it)
}
