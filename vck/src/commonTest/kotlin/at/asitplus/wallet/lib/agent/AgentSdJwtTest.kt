package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.inspectors.forAll
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock

class AgentSdJwtTest : FreeSpec({

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderKeyPair: KeyPairAdapter
    lateinit var challenge: String

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent(
            RandomKeyPairAdapter(),
            issuerCredentialStore,
            DummyCredentialDataProvider(),
        )
        holderKeyPair = RandomKeyPairAdapter()
        holder = HolderAgent(holderKeyPair, holderCredentialStore)
        verifier = VerifierAgent()
        challenge = uuid4().toString()
        holder.storeCredential(
            issuer.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.SD_JWT,
            ).getOrThrow().toStoreCredentialInput()
        )
    }

    val givenNamePresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = listOf(
            InputDescriptor(
                id = uuid4().toString(),
                constraints = Constraint(
                    fields = listOf(
                        ConstraintField(
                            path = listOf("$['given_name']")
                        )
                    )
                )
            )
        )
    )

    "simple walk-through success" {

        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.keyPair.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()
            .also { println("Presentation: ${it.sdJwt}") }

        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        verified.disclosures shouldHaveSize 1
        verified.disclosures.forAll { it.claimName shouldBe "given_name" }
        verified.isRevoked shouldBe false
    }

    "keyBindingJws contains more JWK attributes, still verifies" {
        val sdJwt = createSdJwtPresentation(
            DefaultJwsService(DefaultCryptoService(holderKeyPair)),
            verifier.keyPair.identifier,
            challenge,
            holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>().first(),
            "given_name"
        ).sdJwt
        val verified = verifier.verifyPresentation(sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        verified.disclosures shouldHaveSize 1
        verified.disclosures.forAll { it.claimName shouldBe "given_name" }
        verified.isRevoked shouldBe false
    }

    "wrong key binding jwt" {
        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.keyPair.identifier,
            givenNamePresentationDefinition
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()
        // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
        val malformedVpSdJwt = vp.sdJwt.replaceAfterLast(
            "~",
            createFreshSdJwtKeyBinding(challenge, verifier.keyPair.identifier).substringAfterLast("~")
        )

        verifier.verifyPresentation(malformedVpSdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "wrong challenge in key binding jwt" {
        val malformedChallenge = challenge.reversed()
        val presentationParameters = holder.createPresentation(
            malformedChallenge,
            verifier.keyPair.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "revoked sd jwt" {
        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.keyPair.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrThrow()

        val vp = presentationParameters.presentationResults.firstOrNull()
            .shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        issuer.revokeCredentialsWithId(
            holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .associate { it.sdJwt.jwtId!! to it.sdJwt.notBefore!! }) shouldBe true
        verifier.setRevocationList(issuer.issueRevocationListCredential()!!) shouldBe true
        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
            .shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        verified.isRevoked shouldBe true
    }

})

suspend fun createFreshSdJwtKeyBinding(challenge: String, verifierId: String): String {
    val issuer = IssuerAgent(RandomKeyPairAdapter(), DummyCredentialDataProvider())
    val holderKeyPair = RandomKeyPairAdapter()
    val holder = HolderAgent(holderKeyPair)
    holder.storeCredential(
        issuer.issueCredential(
            holderKeyPair.publicKey,
            ConstantIndex.AtomicAttribute2023,
            ConstantIndex.CredentialRepresentation.SD_JWT,
        ).getOrThrow().toStoreCredentialInput()
    )
    val presentationResult = holder.createPresentation(
        challenge = challenge,
        audienceId = verifierId,
        presentationDefinition = PresentationDefinition(
            id = uuid4().toString(),
            inputDescriptors = listOf(InputDescriptor(id = uuid4().toString()))
        ),
    ).getOrThrow()
    return (presentationResult.presentationResults.first() as Holder.CreatePresentationResult.SdJwt).sdJwt
}

private suspend fun createSdJwtPresentation(
    jwsService: JwsService,
    audienceId: String,
    challenge: String,
    validSdJwtCredential: SubjectCredentialStore.StoreEntry.SdJwt,
    claimName: String,
): Holder.CreatePresentationResult.SdJwt {
    val filteredDisclosures = validSdJwtCredential.disclosures.filter { it.value!!.claimName == claimName }.keys
    val issuerJwtPlusDisclosures =
        SdJwtSigned.sdHashInput(validSdJwtCredential, filteredDisclosures)
    val keyBinding = createKeyBindingJws(jwsService, audienceId, challenge, issuerJwtPlusDisclosures)
    val jwsFromIssuer =
        JwsSigned.parse(validSdJwtCredential.vcSerialized.substringBefore("~")).getOrElse {
            Napier.w("Could not re-create JWS from stored SD-JWT", it)
            throw PresentationException(it)
        }
    val sdJwt =
        SdJwtSigned.serializePresentation(jwsFromIssuer, filteredDisclosures, keyBinding)
    return Holder.CreatePresentationResult.SdJwt(sdJwt)
}

private suspend fun createKeyBindingJws(
    jwsService: JwsService,
    audienceId: String,
    challenge: String,
    issuerJwtPlusDisclosures: String,
): JwsSigned = jwsService.createSignedJwsAddingParams(
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
    ).serialize().encodeToByteArray(),
    addKeyId = false,
    addJsonWebKey = true,
    addX5c = true,
).getOrElse {
    Napier.w("Could not create JWS for presentation", it)
    throw PresentationException(it)
}
