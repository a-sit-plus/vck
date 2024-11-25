package at.asitplus.wallet.lib.agent

import at.asitplus.dif.Constraint
import at.asitplus.dif.ConstraintField
import at.asitplus.dif.DifInputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlinx.serialization.json.jsonPrimitive

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
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(EphemeralKeyWithoutCert(), issuerCredentialStore)
        holderKeyMaterial = EphemeralKeyWithSelfSignedCert()
        holder = HolderAgent(holderKeyMaterial, holderCredentialStore)
        verifierId = "urn:${uuid4()}"
        verifier = VerifierAgent(identifier = verifierId)
        challenge = uuid4().toString()
        holder.storeCredential(
            issuer.issueCredential(
                DummyCredentialDataProvider.getCredential(
                    holderKeyMaterial.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.SD_JWT,
                ).getOrThrow()
            ).getOrThrow().toStoreCredentialInput()
        )
    }

    "simple walk-through success" {
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifierId,
            presentationDefinition = buildPresentationDefinition(CLAIM_GIVEN_NAME, CLAIM_DATE_OF_BIRTH)
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.reconstructedJsonObject[CLAIM_GIVEN_NAME]?.jsonPrimitive?.content shouldBe "Susanne"
        verified.reconstructedJsonObject[CLAIM_DATE_OF_BIRTH]?.jsonPrimitive?.content shouldBe "1990-01-01"
        verified.isRevoked shouldBe false
    }

    "keyBindingJws contains more JWK attributes, still verifies" {
        val credential = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first()
        val sdJwt = createSdJwtPresentation(
            jwsService = DefaultJwsService(DefaultCryptoService(holderKeyMaterial)),
            audienceId = verifierId,
            challenge = challenge,
            validSdJwtCredential = credential,
            claimName = CLAIM_GIVEN_NAME
        ).sdJwt
        val verified = verifier.verifyPresentation(sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()

        verified.reconstructedJsonObject.keys shouldContain CLAIM_GIVEN_NAME
        verified.isRevoked shouldBe false
    }

    "wrong key binding jwt" {
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifierId,
            presentationDefinition = buildPresentationDefinition(CLAIM_GIVEN_NAME)
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()
        // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
        val freshKbJwt = createFreshSdJwtKeyBinding(challenge, verifierId)
        val malformedVpSdJwt = vp.sdJwt.replaceAfterLast("~", freshKbJwt.substringAfterLast("~"))

        verifier.verifyPresentation(malformedVpSdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "wrong challenge in key binding jwt" {
        val malformedChallenge = challenge.reversed()
        val presentationParameters = holder.createPresentation(
            challenge = malformedChallenge,
            audienceId = verifierId,
            presentationDefinition = buildPresentationDefinition(CLAIM_GIVEN_NAME)
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "revoked sd jwt" {
        val presentationParameters = holder.createPresentation(
            challenge = challenge,
            audienceId = verifierId,
            presentationDefinition = buildPresentationDefinition(CLAIM_GIVEN_NAME)
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        val listOfJwtId = holderCredentialStore.getCredentials().getOrThrow()
            .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
            .associate { it.sdJwt.jwtId!! to it.sdJwt.notBefore!! }
        issuer.revokeCredentialsWithId(listOfJwtId) shouldBe true
        verifier.setRevocationList(issuer.issueRevocationListCredential()!!) shouldBe true
        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        verified.isRevoked shouldBe true
    }

})

private fun buildPresentationDefinition(vararg attributeName: String) = PresentationDefinition(
    id = uuid4().toString(),
    inputDescriptors = listOf(
        DifInputDescriptor(
            id = uuid4().toString(),
            constraints = Constraint(
                fields = attributeName.map { ConstraintField(path = listOf("$['$it']")) }
            )
        )
    )
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
        challenge = challenge,
        audienceId = verifierId,
        presentationDefinition = PresentationDefinition(
            id = uuid4().toString(),
            inputDescriptors = listOf(DifInputDescriptor(id = uuid4().toString()))
        ),
    ).getOrThrow()
    val sdJwt = presentationResult.presentationResults.first() as Holder.CreatePresentationResult.SdJwt
    return sdJwt.sdJwt
}

private suspend fun createSdJwtPresentation(
    jwsService: JwsService,
    audienceId: String,
    challenge: String,
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    claimName: String,
): Holder.CreatePresentationResult.SdJwt {
    val filteredDisclosures = validSdJwtCredential.disclosures
        .filter { it.value!!.claimName == claimName }.keys
    val issuerJwtPlusDisclosures = SdJwtSigned.sdHashInput(validSdJwtCredential, filteredDisclosures)
    val keyBinding = createKeyBindingJws(jwsService, audienceId, challenge, issuerJwtPlusDisclosures)
    val sdJwtSerialized = validSdJwtCredential.vcSerialized.substringBefore("~")
    val jwsFromIssuer = JwsSigned.deserialize<VerifiableCredentialSdJwt>(sdJwtSerialized).getOrElse {
        Napier.w("Could not re-create JWS from stored SD-JWT", it)
        throw PresentationException(it)
    }
    val sdJwt = SdJwtSigned.serializePresentation(jwsFromIssuer, filteredDisclosures, keyBinding)
    return Holder.CreatePresentationResult.SdJwt(sdJwt)
}

private suspend fun createKeyBindingJws(
    jwsService: JwsService,
    audienceId: String,
    challenge: String,
    issuerJwtPlusDisclosures: String,
): JwsSigned<KeyBindingJws> = jwsService.createSignedJwsAddingParams(
    header = JwsHeader(
        type = JwsContentTypeConstants.KB_JWT,
        algorithm = jwsService.algorithm,
        keyId = "definitely not matching"
    ),
    payload = KeyBindingJws(
        issuedAt = Clock.System.now(),
        audience = audienceId,
        challenge = challenge,
        sdHash = issuerJwtPlusDisclosures.encodeToByteArray().sha256(),
    ),
    serializer = KeyBindingJws.serializer(),
    addKeyId = false,
    addJsonWebKey = true,
    addX5c = true,
).getOrElse {
    Napier.w("Could not create JWS for presentation", it)
    throw PresentationException(it)
}
