@file:Suppress("unused")

package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.inspectors.forAll
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

class AgentSdJwtTest : FreeSpec({

    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var issuerCredentialStore: IssuerCredentialStore
    lateinit var holderCredentialStore: SubjectCredentialStore
    lateinit var holderCryptoService: CryptoService
    lateinit var challenge: String

    beforeEach {
        issuerCredentialStore = InMemoryIssuerCredentialStore()
        holderCredentialStore = InMemorySubjectCredentialStore()
        issuer = IssuerAgent.newDefaultInstance(
            issuerCredentialStore = issuerCredentialStore,
            dataProvider = DummyCredentialDataProvider(),
        )
        holderCryptoService = DefaultCryptoService()
        holder = HolderAgent(holderCryptoService, holderCredentialStore)
        verifier = VerifierAgent()
        challenge = uuid4().toString()
    }

    val givenNamePresentationDefinition = PresentationDefinition(
        id = uuid4().toString(),
        inputDescriptors = listOf(
            InputDescriptor(
                id = uuid4().toString(),
                constraints = Constraint(
                    fields = listOf(
                        ConstraintField(
                            path = listOf("$['given-name']")
                        )
                    )
                )
            )
        )
    )

    "simple walk-through success" {
        issueDummyCredentials(holder, issuer, holderCryptoService)
        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp shouldNotBe null
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()
        println("Presentation: " + vp.sdJwt)

        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        verified.disclosures shouldHaveSize 1
        verified.disclosures.forAll { it.claimName shouldBe "given-name" }
        verified.isRevoked shouldBe false
    }

    "wrong key binding jwt" {
        issueDummyCredentials(holder, issuer, holderCryptoService)
        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp shouldNotBe null
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()
        // replace key binding of original vp.sdJwt (i.e. the part after the last `~`)
        val malformedVpSdJwt = vp.sdJwt.replaceAfterLast(
            "~",
            createFreshSdJwtKeyBinding(challenge, verifier.identifier).substringAfterLast("~")
        )

        val verified = verifier.verifyPresentation(malformedVpSdJwt, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "wrong challenge in key binding jwt" {
        issueDummyCredentials(holder, issuer, holderCryptoService)
        val malformedChallenge = challenge.reversed()
        val presentationParameters = holder.createPresentation(
            malformedChallenge,
            verifier.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp shouldNotBe null
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.InvalidStructure>()
    }

    "revoked sd jwt" {
        issueDummyCredentials(holder, issuer, holderCryptoService)
        val presentationParameters = holder.createPresentation(
            challenge,
            verifier.identifier,
            presentationDefinition = givenNamePresentationDefinition
        ).getOrNull()
        presentationParameters.shouldNotBeNull()
        val vp = presentationParameters.presentationResults.firstOrNull()
        vp shouldNotBe null
        vp.shouldBeInstanceOf<Holder.CreatePresentationResult.SdJwt>()

        issuer.revokeCredentialsWithId(
            holderCredentialStore.getCredentials().getOrThrow()
                .filterIsInstance<SubjectCredentialStore.StoreEntry.SdJwt>()
                .associate { it.sdJwt.jwtId!! to it.sdJwt.notBefore!! }) shouldBe true
        verifier.setRevocationList(issuer.issueRevocationListCredential()!!) shouldBe true
        val verified = verifier.verifyPresentation(vp.sdJwt, challenge)
        verified.shouldBeInstanceOf<Verifier.VerifyPresentationResult.SuccessSdJwt>()
        verified.isRevoked shouldBe true
    }

})

suspend fun createFreshSdJwtKeyBinding(challenge: String, verifierId: String): String {
    val issuer = IssuerAgent.newDefaultInstance(
        dataProvider = DummyCredentialDataProvider(),
    )
    val holderCryptoService = DefaultCryptoService()
    val holder = HolderAgent(holderCryptoService)
    issueDummyCredentials(holder, issuer, holderCryptoService)
    val presentationResult = holder.createPresentation(
        challenge = challenge,
        audienceId = verifierId,
        presentationDefinition = PresentationDefinition(
            id = uuid4().toString(),
            inputDescriptors = listOf(InputDescriptor(id = uuid4().toString()))
        ),
    ).getOrNull()
    return (presentationResult?.presentationResults?.first() as Holder.CreatePresentationResult.SdJwt).sdJwt
}

suspend fun issueDummyCredentials(
    holder: Holder,
    issuer: Issuer,
    holderCryptoService: CryptoService
) {
    val result = issuer.issueCredential(
        subjectPublicKey = holderCryptoService.publicKey,
        attributeTypes = listOf(ConstantIndex.AtomicAttribute2023.vcType),
        representation = ConstantIndex.CredentialRepresentation.SD_JWT,
    )
    result.successful.shouldNotBeEmpty()
    holder.storeCredentials(result.toStoreCredentialInput())
}