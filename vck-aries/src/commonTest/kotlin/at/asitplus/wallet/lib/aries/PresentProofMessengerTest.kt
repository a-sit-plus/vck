package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class PresentProofMessengerTest : FreeSpec() {

    private lateinit var holderKeyPair: KeyWithCert
    private lateinit var verifierKeyPair: KeyWithCert
    private lateinit var issuerKeyPair: KeyWithCert
    private lateinit var holderCredentialStore: SubjectCredentialStore
    private lateinit var holder: Holder
    private lateinit var verifier: Verifier
    private lateinit var issuer: Issuer
    private lateinit var verifierChallenge: String
    private lateinit var holderServiceEndpoint: String
    private var attributeLifetime: Duration = 5.toDuration(DurationUnit.SECONDS)

    init {

        beforeEach {
            holderKeyPair = EphemeralKeyWithSelfSignedCert()
            verifierKeyPair = EphemeralKeyWithSelfSignedCert()
            issuerKeyPair = EphemeralKeyWithSelfSignedCert()
            holderCredentialStore = InMemorySubjectCredentialStore()
            holder = HolderAgent(holderKeyPair, holderCredentialStore)
            verifier = VerifierAgent(verifierKeyPair)
            issuer = IssuerAgent(issuerKeyPair, DummyCredentialDataProvider())
            verifierChallenge = uuid4().toString()
            holderServiceEndpoint = "https://example.com/present-proof?${uuid4()}"
        }

        "presentProof" {
            holder.storeCredential(
                issuer.issueCredential(
                    holderKeyPair.publicKey,
                    ConstantIndex.AtomicAttribute2023,
                    ConstantIndex.CredentialRepresentation.PLAIN_JWT
                ).getOrThrow().toStoreCredentialInput()
            )
            val holderMessenger = PresentProofMessenger.newHolderInstance(
                holder = holder,
                messageWrapper = MessageWrapper(holderKeyPair),
                serviceEndpoint = holderServiceEndpoint,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
            )
            val verifierMessenger = PresentProofMessenger.newVerifierInstance(
                verifier = verifier,
                messageWrapper = MessageWrapper(verifierKeyPair),
                credentialScheme = ConstantIndex.AtomicAttribute2023,
            )

            val oobInvitation = holderMessenger.startCreatingInvitation()
            oobInvitation.shouldBeInstanceOf<NextMessage.Send>()
            val invitationMessage = oobInvitation.message

            val parsedInvitation = verifierMessenger.parseMessage(invitationMessage)
            parsedInvitation.shouldBeInstanceOf<NextMessage.Send>()
            parsedInvitation.endpoint shouldBe holderServiceEndpoint
            val requestPresentation = parsedInvitation.message

            val parsedRequestPresentation = holderMessenger.parseMessage(requestPresentation)
            parsedRequestPresentation.shouldBeInstanceOf<NextMessage.Send>()
            val presentation = parsedRequestPresentation.message

            val parsePresentation = verifierMessenger.parseMessage(presentation)
            parsePresentation.shouldBeInstanceOf<NextMessage.Result<PresentProofProtocolResult>>()
            val vpResult = parsePresentation.result

            vpResult.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
            vpResult.vp.verifiableCredentials.shouldNotBeEmpty()
        }

        "selectiveDisclosure" {
            val issuedCredential = issuer.issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).getOrThrow()
            holder.storeCredential(issuedCredential.toStoreCredentialInput())
            val expectedSubject = holderCredentialStore.getCredentials().getOrThrow().first()
                    as SubjectCredentialStore.StoreEntry.Vc
            val subject = expectedSubject.vc.vc.credentialSubject as AtomicAttribute2023
            val attributeName = subject.name
            val attributeValue = subject.value

            val holderMessenger = PresentProofMessenger.newHolderInstance(
                holder = holder,
                messageWrapper = MessageWrapper(holderKeyPair),
                serviceEndpoint = "https://example.com",
                credentialScheme = ConstantIndex.AtomicAttribute2023,
            )
            val verifierMessenger = PresentProofMessenger.newVerifierInstance(
                verifier = verifier,
                messageWrapper = MessageWrapper(verifierKeyPair),
                challengeForPresentation = verifierChallenge,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                requestedClaims = listOf(attributeName)
            )

            val oobInvitation = holderMessenger.startCreatingInvitation()
            oobInvitation.shouldBeInstanceOf<NextMessage.Send>()
            val invitationMessage = oobInvitation.message

            val parsedInvitation = verifierMessenger.parseMessage(invitationMessage)
            parsedInvitation.shouldBeInstanceOf<NextMessage.Send>()
            val requestPresentation = parsedInvitation.message

            val parsedRequestPresentation = holderMessenger.parseMessage(requestPresentation)
            parsedRequestPresentation.shouldBeInstanceOf<NextMessage.Send>()
            val presentation = parsedRequestPresentation.message

            val parsePresentation = verifierMessenger.parseMessage(presentation)
            parsePresentation.shouldBeInstanceOf<NextMessage.Result<PresentProofProtocolResult>>()
            val receivedPresentation = parsePresentation.result

            // TODO assertPresentation(receivedPresentation, attributeName, attributeValue)
            // TODO test with SD JWT or something supported
        }
    }

    private fun assertPresentation(
        vpResult: PresentProofProtocolResult,
        attributeName: String,
        attributeValue: String
    ) {
        vpResult.shouldBeInstanceOf<Verifier.VerifyPresentationResult.Success>()
        val vp = vpResult.vp
        vp.verifiableCredentials shouldHaveSize 1
        vp.verifiableCredentials.forEach {
            it.vc.credentialSubject.shouldBeInstanceOf<AtomicAttribute2023>()
            (it.vc.credentialSubject as AtomicAttribute2023).name shouldBe attributeName
            (it.vc.credentialSubject as AtomicAttribute2023).value shouldBe attributeValue
        }
    }

    private fun randomCredential(subjectId: String) = CredentialToBeIssued.VcJwt(
        subject = AtomicAttribute2023(subjectId, uuid4().toString(), uuid4().toString()),
        expiration = Clock.System.now() + attributeLifetime,
    )

}