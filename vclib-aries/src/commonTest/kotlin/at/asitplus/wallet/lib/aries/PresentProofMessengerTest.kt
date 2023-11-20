package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
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

    private lateinit var holderCryptoService: CryptoService
    private lateinit var verifierCryptoService: CryptoService
    private lateinit var issuerCryptoService: CryptoService
    private lateinit var holder: Holder
    private lateinit var verifier: Verifier
    private lateinit var issuer: Issuer
    private lateinit var verifierChallenge: String
    private lateinit var holderServiceEndpoint: String
    private var attributeLifetime: Duration = 5.toDuration(DurationUnit.SECONDS)

    init {

        beforeEach {
            holderCryptoService = DefaultCryptoService()
            verifierCryptoService = DefaultCryptoService()
            issuerCryptoService = DefaultCryptoService()
            holder = HolderAgent.newDefaultInstance(holderCryptoService)
            verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.jsonWebKey.identifier)
            issuer = IssuerAgent.newDefaultInstance(issuerCryptoService)
            verifierChallenge = uuid4().toString()
            holderServiceEndpoint = "https://example.com/present-proof?${uuid4()}"
        }

        "presentProof" {
            val credentialSubject = randomCredential(holderCryptoService.jsonWebKey.identifier)
            holder.storeCredentials(issuer.issueCredential(credentialSubject).toStoreCredentialInput())
            val holderMessenger = PresentProofMessenger.newHolderInstance(
                holder = holder,
                messageWrapper = MessageWrapper(holderCryptoService),
                serviceEndpoint = holderServiceEndpoint,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
            )
            val verifierMessenger = PresentProofMessenger.newVerifierInstance(
                verifier = verifier,
                messageWrapper = MessageWrapper(verifierCryptoService),
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
            val expectedSubject = randomCredential(holder.identifier)
            val subject = expectedSubject.subject
            val attributeName = (subject as AtomicAttribute2023).name
            val attributeValue = (subject as AtomicAttribute2023).value
            val expectedVc = issuer.issueCredential(expectedSubject)
            holder.storeCredentials(expectedVc.toStoreCredentialInput())

            val holderMessenger = PresentProofMessenger.newHolderInstance(
                holder = holder,
                messageWrapper = MessageWrapper(holderCryptoService),
                serviceEndpoint = "https://example.com",
                credentialScheme = ConstantIndex.AtomicAttribute2023,
            )
            val verifierMessenger = PresentProofMessenger.newVerifierInstance(
                verifier = verifier,
                messageWrapper = MessageWrapper(verifierCryptoService),
                challengeForPresentation = verifierChallenge,
                credentialScheme = ConstantIndex.AtomicAttribute2023,
                requestedAttributeTypes = listOf(attributeName)
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

            assertPresentation(receivedPresentation, attributeName, attributeValue)
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

    private fun randomCredential(subjectId: String) = CredentialToBeIssued.Vc(
        AtomicAttribute2023(
            subjectId,
            uuid4().toString(),
            uuid4().toString(),
            "application/text"
        ),
        Clock.System.now() + attributeLifetime,
        ConstantIndex.AtomicAttribute2023.vcType
    )

}