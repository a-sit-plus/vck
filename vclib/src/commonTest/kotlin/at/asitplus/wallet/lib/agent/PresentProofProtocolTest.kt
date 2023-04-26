package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.msg.JwmAttachmentData
import at.asitplus.wallet.lib.msg.JwmAttachment
import at.asitplus.wallet.lib.msg.Presentation
import at.asitplus.wallet.lib.msg.RequestCredential
import at.asitplus.wallet.lib.msg.RequestCredentialBody
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

class PresentProofProtocolTest : FreeSpec({

    lateinit var holderCryptoService: CryptoService
    lateinit var verifierCryptoService: CryptoService
    lateinit var holder: Holder
    lateinit var verifier: Verifier
    lateinit var holderProtocol: PresentProofProtocol
    lateinit var verifierProtocol: PresentProofProtocol

    beforeEach {
        holderCryptoService = DefaultCryptoService()
        verifierCryptoService = DefaultCryptoService()
        holder = HolderAgent.newDefaultInstance(holderCryptoService)
        verifier = VerifierAgent.newDefaultInstance(verifierCryptoService.keyId)
        holderProtocol = PresentProofProtocol.newHolderInstance(
            holder,
            holderCryptoService.keyId,
            "https://example.com/"
        )
        verifierProtocol =
            PresentProofProtocol.newVerifierInstance(verifier, verifierCryptoService.keyId)
    }

    "presentProofGenericWithInvitation" {
        holder.storeCredentials(
            IssuerAgent.newDefaultInstance(
                DefaultCryptoService(),
                dataProvider = DummyCredentialDataProvider(),
            ).issueCredentialWithTypes(
                holderCryptoService.keyId,
                listOf(ConstantIndex.Generic.vcType)
            ).toStoreCredentialInput()
        )

        val oobInvitation = holderProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation =
            verifierProtocol.parseMessage(invitationMessage, holderCryptoService.keyId)
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestPresentation = parsedInvitation.message

        val parsedRequestPresentation =
            holderProtocol.parseMessage(requestPresentation, verifierCryptoService.keyId)
        parsedRequestPresentation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val presentation = parsedRequestPresentation.message

        val parsedPresentation =
            verifierProtocol.parseMessage(presentation, holderCryptoService.keyId)
        parsedPresentation.shouldBeInstanceOf<InternalNextMessage.Finished>()

        val receivedPresentation = parsedPresentation.lastMessage
        receivedPresentation.shouldBeInstanceOf<Presentation>()
    }

    "presentProofGenericDirect" {
        holder.storeCredentials(
            IssuerAgent.newDefaultInstance(
                DefaultCryptoService(),
                dataProvider = DummyCredentialDataProvider(),
            ).issueCredentialWithTypes(
                holderCryptoService.keyId,
                listOf(ConstantIndex.Generic.vcType)
            ).toStoreCredentialInput()
        )

        val requestPresentation = verifierProtocol.startDirect()
        requestPresentation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()

        val parsedRequestPresentation = holderProtocol.parseMessage(
            requestPresentation.message,
            verifierCryptoService.keyId
        )
        parsedRequestPresentation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val presentation = parsedRequestPresentation.message

        val parsedPresentation =
            verifierProtocol.parseMessage(presentation, holderCryptoService.keyId)
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
            holderCryptoService.keyId
        )
        parsed.shouldBeInstanceOf<InternalNextMessage.IncorrectState>()
    }

    "emptyPresentationProblemReport" {
        val oobInvitation = holderProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation =
            verifierProtocol.parseMessage(invitationMessage, holderCryptoService.keyId)
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestPresentation = parsedInvitation.message

        val parsedRequestPresentation =
            holderProtocol.parseMessage(requestPresentation, verifierCryptoService.keyId)
        parsedRequestPresentation.shouldBeInstanceOf<InternalNextMessage.SendProblemReport>()
        val problemReport = parsedRequestPresentation.message

        requestPresentation.threadId shouldBe problemReport.parentThreadId
    }

})
