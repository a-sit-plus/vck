package at.asitplus.wallet.lib.aries

import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.msg.AttachmentFormatReference
import at.asitplus.wallet.lib.msg.IssueCredential
import at.asitplus.wallet.lib.msg.JwmAttachment
import at.asitplus.wallet.lib.msg.JwmAttachmentData
import at.asitplus.wallet.lib.msg.Presentation
import at.asitplus.wallet.lib.msg.PresentationBody
import at.asitplus.wallet.lib.msg.RequestCredential
import at.asitplus.wallet.lib.msg.RequestCredentialBody
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

class IssueCredentialProtocolTest : FreeSpec({

    lateinit var issuerCryptoService: CryptoService
    lateinit var holderCryptoService: CryptoService
    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var issuerProtocol: IssueCredentialProtocol
    lateinit var holderProtocol: IssueCredentialProtocol

    beforeEach {
        issuerCryptoService = DefaultCryptoService()
        holderCryptoService = DefaultCryptoService()
        issuer = IssuerAgent.newDefaultInstance(issuerCryptoService, dataProvider = DummyCredentialDataProvider())
        holder = HolderAgent.newDefaultInstance(holderCryptoService)
        issuerProtocol = IssueCredentialProtocol.newIssuerInstance(
            issuer = issuer,
            serviceEndpoint = "https://example.com/issue?${uuid4()}",
            credentialScheme = ConstantIndex.AtomicAttribute2023,
        )
        holderProtocol = IssueCredentialProtocol.newHolderInstance(
            holder = holder,
            credentialScheme = ConstantIndex.AtomicAttribute2023,
        )
    }

    "issueCredentialGenericWithInvitation" {
        val oobInvitation = issuerProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation = holderProtocol.parseMessage(invitationMessage, issuerCryptoService.toPublicKey().toJsonWebKey())
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestCredential = parsedInvitation.message

        val parsedRequestCredential = issuerProtocol.parseMessage(requestCredential, holderCryptoService.toPublicKey().toJsonWebKey())
        parsedRequestCredential.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val issueCredential = parsedRequestCredential.message

        val parsedIssueCredential = holderProtocol.parseMessage(issueCredential, issuerCryptoService.toPublicKey().toJsonWebKey())
        parsedIssueCredential.shouldBeInstanceOf<InternalNextMessage.Finished>()

        val issuedCredential = parsedIssueCredential.lastMessage
        issuedCredential.shouldBeInstanceOf<IssueCredential>()
    }

    "issueCredentialGenericDirect" {
        val requestCredential = holderProtocol.startDirect()
        requestCredential.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()

        val parsedRequestCredential =
            issuerProtocol.parseMessage(requestCredential.message, holderCryptoService.toPublicKey().toJsonWebKey())
        parsedRequestCredential.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val issueCredential = parsedRequestCredential.message

        val parsedIssueCredential = holderProtocol.parseMessage(issueCredential, issuerCryptoService.toPublicKey().toJsonWebKey())
        parsedIssueCredential.shouldBeInstanceOf<InternalNextMessage.Finished>()

        val issuedCredential = parsedIssueCredential.lastMessage
        issuedCredential.shouldBeInstanceOf<IssueCredential>()
    }

    "wrongStartMessage" {
        val parsed = holderProtocol.parseMessage(
            Presentation(
                body = PresentationBody("foo", arrayOf(AttachmentFormatReference("id1", "jws"))),
                threadId = uuid4().toString(),
                attachment = JwmAttachment(id = uuid4().toString(), "mimeType", JwmAttachmentData())
            ),
            issuerCryptoService.toPublicKey().toJsonWebKey()
        )
        parsed.shouldBeInstanceOf<InternalNextMessage.IncorrectState>()
    }

    "wrongRequestCredentialMessage" {
        val oobInvitation = issuerProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation = holderProtocol.parseMessage(invitationMessage, issuerCryptoService.toPublicKey().toJsonWebKey())
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestCredential = parsedInvitation.message

        val wrongRequestCredential = RequestCredential(
            body = RequestCredentialBody(
                comment = "something",
                goalCode = "issue-vc-${ConstantIndex.AtomicAttribute2023.credentialDefinitionName}",
                formats = arrayOf()
            ),
            parentThreadId = requestCredential.parentThreadId!!,
            attachment = JwmAttachment(
                id = uuid4().toString(),
                mediaType = "unknown",
                data = JwmAttachmentData()
            )
        )
        val parsedRequestCredential =
            issuerProtocol.parseMessage(wrongRequestCredential, holderCryptoService.toPublicKey().toJsonWebKey())
        parsedRequestCredential.shouldBeInstanceOf<InternalNextMessage.SendProblemReport>()
        val problemReport = parsedRequestCredential.message

        problemReport.parentThreadId shouldNotBe null
    }
})