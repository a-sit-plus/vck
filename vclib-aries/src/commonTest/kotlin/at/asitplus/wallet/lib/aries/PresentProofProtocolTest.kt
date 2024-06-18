package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.msg.*
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class PresentProofProtocolTest : FreeSpec({

    lateinit var holderKeyPair: KeyPairAdapter
    lateinit var verifierKeyPair: KeyPairAdapter
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var holderProtocol: PresentProofProtocol
    lateinit var verifierProtocol: PresentProofProtocol

    beforeEach {
        holderKeyPair = RandomKeyPairAdapter()
        verifierKeyPair = RandomKeyPairAdapter()
        holder = HolderAgent(holderKeyPair)
        verifier = VerifierAgent(verifierKeyPair)
        holderProtocol = PresentProofProtocol.newHolderInstance(
            holder = holder,
            serviceEndpoint = "https://example.com/",
            credentialScheme = ConstantIndex.AtomicAttribute2023,
        )
        verifierProtocol = PresentProofProtocol.newVerifierInstance(
            verifier = verifier,
            credentialScheme = ConstantIndex.AtomicAttribute2023,
        )
    }

    "presentProofGenericWithInvitation" {
        holder.storeCredentials(
            IssuerAgent(
                RandomKeyPairAdapter(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).toStoreCredentialInput()
        )

        val oobInvitation = holderProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation =
            verifierProtocol.parseMessage(invitationMessage, holderKeyPair.jsonWebKey)
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestPresentation = parsedInvitation.message

        val parsedRequestPresentation =
            holderProtocol.parseMessage(requestPresentation, verifierKeyPair.jsonWebKey)
        parsedRequestPresentation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val presentation = parsedRequestPresentation.message

        val parsedPresentation =
            verifierProtocol.parseMessage(presentation, holderKeyPair.jsonWebKey)
        parsedPresentation.shouldBeInstanceOf<InternalNextMessage.Finished>()

        val receivedPresentation = parsedPresentation.lastMessage
        receivedPresentation.shouldBeInstanceOf<Presentation>()
    }

    "presentProofGenericDirect" {
        holder.storeCredentials(
            IssuerAgent(
                RandomKeyPairAdapter(),
                DummyCredentialDataProvider(),
            ).issueCredential(
                holderKeyPair.publicKey,
                ConstantIndex.AtomicAttribute2023,
                ConstantIndex.CredentialRepresentation.PLAIN_JWT
            ).toStoreCredentialInput()
        )

        val requestPresentation = verifierProtocol.startDirect()
        requestPresentation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()

        val parsedRequestPresentation =
            holderProtocol.parseMessage(requestPresentation.message, verifierKeyPair.jsonWebKey)
        parsedRequestPresentation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val presentation = parsedRequestPresentation.message

        val parsedPresentation =
            verifierProtocol.parseMessage(presentation, holderKeyPair.jsonWebKey)
        parsedPresentation.shouldBeInstanceOf<InternalNextMessage.Finished>()

        val receivedPresentation = parsedPresentation.lastMessage
        receivedPresentation.shouldBeInstanceOf<Presentation>()
    }

    "wrongStartMessage" {
        val parsed = verifierProtocol.parseMessage(
            RequestCredential(
                body = RequestCredentialBody("foo", "goalCode", arrayOf()),
                parentThreadId = uuid4().toString(),
                attachment = JwmAttachment(id = uuid4().toString(), "mimeType", JwmAttachmentData())
            ),
            holderKeyPair.jsonWebKey
        )
        parsed.shouldBeInstanceOf<InternalNextMessage.IncorrectState>()
    }

    "emptyPresentationProblemReport" {
        val oobInvitation = holderProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation =
            verifierProtocol.parseMessage(invitationMessage, holderKeyPair.jsonWebKey)
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestPresentation = parsedInvitation.message

        val parsedRequestPresentation =
            holderProtocol.parseMessage(requestPresentation, verifierKeyPair.jsonWebKey)
        parsedRequestPresentation.shouldBeInstanceOf<InternalNextMessage.SendProblemReport>()
        val problemReport = parsedRequestPresentation.message

        requestPresentation.threadId shouldBe problemReport.parentThreadId
    }

})