package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.data.AriesGoalCodeParser
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.msg.*
import com.benasher44.uuid.uuid4
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

class IssueCredentialProtocolTest : FreeSpec({

    lateinit var issuerKeyPair: KeyMaterial
    lateinit var holderKeyPair: KeyMaterial
    lateinit var issuer: Issuer
    lateinit var holder: Holder
    lateinit var issuerProtocol: IssueCredentialProtocol
    lateinit var holderProtocol: IssueCredentialProtocol

    beforeEach {
        issuerKeyPair = EphemeralKeyWithSelfSignedCert()
        holderKeyPair = EphemeralKeyWithSelfSignedCert()
        issuer = IssuerAgent(issuerKeyPair, DummyCredentialDataProvider())
        holder = HolderAgent(holderKeyPair)
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

        val parsedInvitation =
            holderProtocol.parseMessage(invitationMessage, issuerKeyPair.jsonWebKey)
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestCredential = parsedInvitation.message

        val parsedRequestCredential =
            issuerProtocol.parseMessage(requestCredential, holderKeyPair.jsonWebKey)
        parsedRequestCredential.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val issueCredential = parsedRequestCredential.message

        val parsedIssueCredential =
            holderProtocol.parseMessage(issueCredential, issuerKeyPair.jsonWebKey)
        parsedIssueCredential.shouldBeInstanceOf<InternalNextMessage.Finished>()

        val issuedCredential = parsedIssueCredential.lastMessage
        issuedCredential.shouldBeInstanceOf<IssueCredential>()
    }

    "issueCredentialGenericDirect" {
        val requestCredential = holderProtocol.startDirect()
        requestCredential.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()

        val parsedRequestCredential =
            issuerProtocol.parseMessage(requestCredential.message, holderKeyPair.jsonWebKey)
        parsedRequestCredential.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val issueCredential = parsedRequestCredential.message

        val parsedIssueCredential =
            holderProtocol.parseMessage(issueCredential, issuerKeyPair.jsonWebKey)
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
            issuerKeyPair.jsonWebKey
        )
        parsed.shouldBeInstanceOf<InternalNextMessage.IncorrectState>()
    }

    "wrongRequestCredentialMessage" {
        val oobInvitation = issuerProtocol.startCreatingInvitation()
        oobInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val invitationMessage = oobInvitation.message

        val parsedInvitation =
            holderProtocol.parseMessage(invitationMessage, issuerKeyPair.jsonWebKey)
        parsedInvitation.shouldBeInstanceOf<InternalNextMessage.SendAndWrap>()
        val requestCredential = parsedInvitation.message

        val wrongRequestCredential = RequestCredential(
            body = RequestCredentialBody(
                comment = "something",
                goalCode = "issue-vc-${AriesGoalCodeParser.getAriesName(ConstantIndex.AtomicAttribute2023)}",
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
            issuerProtocol.parseMessage(wrongRequestCredential, holderKeyPair.jsonWebKey)
        parsedRequestCredential.shouldBeInstanceOf<InternalNextMessage.SendProblemReport>()
        val problemReport = parsedRequestCredential.message

        problemReport.parentThreadId shouldNotBe null
    }
})