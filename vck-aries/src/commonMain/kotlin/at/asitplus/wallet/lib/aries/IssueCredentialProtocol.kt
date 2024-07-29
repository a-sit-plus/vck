package at.asitplus.wallet.lib.aries

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.wallet.lib.DataSourceProblem
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.AriesGoalCodeParser
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.data.dif.CredentialDefinition
import at.asitplus.wallet.lib.data.dif.CredentialManifest
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.msg.AttachmentFormatReference
import at.asitplus.wallet.lib.msg.IssueCredential
import at.asitplus.wallet.lib.msg.IssueCredentialBody
import at.asitplus.wallet.lib.msg.JsonWebMessage
import at.asitplus.wallet.lib.msg.JwmAttachment
import at.asitplus.wallet.lib.msg.OutOfBandInvitation
import at.asitplus.wallet.lib.msg.OutOfBandInvitationBody
import at.asitplus.wallet.lib.msg.OutOfBandService
import at.asitplus.wallet.lib.msg.RequestCredential
import at.asitplus.wallet.lib.msg.RequestCredentialAttachment
import at.asitplus.wallet.lib.msg.RequestCredentialBody
import io.github.aakira.napier.Napier
import kotlinx.serialization.encodeToString

typealias IssueCredentialProtocolResult = KmmResult<Holder.StoredCredential>

/**
 * Use this class for exactly one instance of a protocol run.
 *
 * Implements a trimmed-down version of
 * [ARIES RFC 0453 Issue Credential V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2)
 * and uses
 * [DIF Credential Manifest](https://identity.foundation/credential-manifest/)
 * for
 * [attachments](https://github.com/hyperledger/aries-rfcs/blob/main/features/0511-dif-cred-manifest-attach).
 *
 * If [holder] is passed as `null`, no verification of the received messages will happen!
 */
class IssueCredentialProtocol(
    private val issuer: Issuer? = null,
    private val holder: Holder? = null,
    private val serviceEndpoint: String? = null,
    private val credentialScheme: ConstantIndex.CredentialScheme
) : ProtocolStateMachine<IssueCredentialProtocolResult> {

    companion object {
        /**
         * Creates a new instance of this protocol for the Holder side,
         * it will receive the Verifiable Credentials and validate them.
         */
        fun newHolderInstance(
            holder: Holder,
            credentialScheme: ConstantIndex.CredentialScheme,
        ) = IssueCredentialProtocol(
            holder = holder,
            credentialScheme = credentialScheme,
        )

        /**
         * Creates a new instance of this protocol for the Issuer side,
         * it will issue the Verifiable Credentials.
         */
        fun newIssuerInstance(
            issuer: Issuer,
            serviceEndpoint: String? = null,
            credentialScheme: ConstantIndex.CredentialScheme,
        ) = IssueCredentialProtocol(
            issuer = issuer,
            serviceEndpoint = serviceEndpoint,
            credentialScheme = credentialScheme,
        )
    }

    private var result: IssueCredentialProtocolResult? = null
    private val problemReporter = ProblemReporter()
    private var state: State = State.START
    private var invitationId: String? = null
    private var threadId: String? = null

    enum class State {
        START,
        INVITATION_SENT,
        REQUEST_CREDENTIAL_SENT,
        FINISHED
    }

    override fun startCreatingInvitation(): InternalNextMessage {
        if (this.state != State.START)
            return InternalNextMessage.IncorrectState("state")
                .also { Napier.w("Unexpected state: $state") }
        Napier.d("Start IssueCredentialProtocol with oobInvitation")
        return createOobInvitation()
    }

    override fun startDirect(): InternalNextMessage {
        if (this.state != State.START)
            return InternalNextMessage.IncorrectState("state")
                .also { Napier.w("Unexpected state: $state") }
        Napier.d("Start IssueCredentialProtocol with requestCredential")
        return createRequestCredential()
    }

    override suspend fun parseMessage(body: JsonWebMessage, senderKey: JsonWebKey): InternalNextMessage {
        when (this.state) {
            State.START -> {
                if (body is OutOfBandInvitation)
                    return createRequestCredential(body, senderKey)
                if (body is RequestCredential)
                    return issueCredential(body, senderKey)
                return InternalNextMessage.IncorrectState("messageType")
                    .also { Napier.w("Unexpected messageType: ${body.type}") }
            }

            State.INVITATION_SENT -> {
                if (body !is RequestCredential)
                    return InternalNextMessage.IncorrectState("messageType")
                        .also { Napier.w("Unexpected messageType: ${body.type}") }
                if (body.parentThreadId != invitationId)
                    return InternalNextMessage.IncorrectState("parentThreadId")
                        .also { Napier.w("Unexpected parentThreadId: ${body.parentThreadId}") }
                return issueCredential(body, senderKey)
            }

            State.REQUEST_CREDENTIAL_SENT -> {
                if (body !is IssueCredential)
                    return InternalNextMessage.IncorrectState("messageType")
                        .also { Napier.w("Unexpected messageType: ${body.type}") }
                if (body.threadId != threadId)
                    return InternalNextMessage.IncorrectState("threadId")
                        .also { Napier.w("Unexpected threadId: ${body.threadId}") }
                return storeCredentials(body)
            }

            else -> return InternalNextMessage.IncorrectState("state")
                .also { Napier.w("Unexpected internal state: $state") }
        }
    }

    private fun createOobInvitation(): InternalNextMessage {
        val recipientKey = issuer?.keyPair?.identifier
            ?: return InternalNextMessage.IncorrectState("issuer")
        val message = OutOfBandInvitation(
            body = OutOfBandInvitationBody(
                handshakeProtocols = arrayOf(SchemaIndex.PROT_ISSUE_CRED),
                acceptTypes = arrayOf("application/didcomm-signed+json"),
                goalCode = "issue-vc-${AriesGoalCodeParser.getAriesName(credentialScheme)}",
                services = arrayOf(
                    OutOfBandService(
                        type = "did-communication",
                        recipientKeys = arrayOf(recipientKey),
                        serviceEndpoint = serviceEndpoint ?: "https://example.com",
                    )
                )
            )
        )
        return InternalNextMessage.SendAndWrap(message)
            .also { this.invitationId = message.id }
            .also { this.state = State.INVITATION_SENT }
    }

    private fun createRequestCredential(): InternalNextMessage {
        val message = buildRequestCredentialMessage(credentialScheme)
            ?: return InternalNextMessage.IncorrectState("holder")
        return InternalNextMessage.SendAndWrap(message)
            .also { this.threadId = message.threadId }
            .also { this.state = State.REQUEST_CREDENTIAL_SENT }
    }

    private fun createRequestCredential(invitation: OutOfBandInvitation, senderKey: JsonWebKey): InternalNextMessage {
        val credentialScheme = AriesGoalCodeParser.parseGoalCode(invitation.body.goalCode)
            ?: return problemReporter.problemLastMessage(invitation.threadId, "goal-code-unknown")
        val message = buildRequestCredentialMessage(credentialScheme, invitation.id)
            ?: return InternalNextMessage.IncorrectState("holder")
        val serviceEndpoint = invitation.body.services?.let {
            if (it.isNotEmpty()) it[0].serviceEndpoint else null
        }
        return InternalNextMessage.SendAndWrap(message, senderKey, serviceEndpoint)
            .also { this.threadId = message.threadId }
            .also { this.state = State.REQUEST_CREDENTIAL_SENT }
    }

    private fun buildRequestCredentialMessage(
        credentialScheme: ConstantIndex.CredentialScheme,
        parentThreadId: String? = null,
    ): RequestCredential? {
        val subject = holder?.keyPair?.identifier ?: return null
        val credentialManifest = CredentialManifest(
            issuer = "somebody",
            subject = subject,
            credential = CredentialDefinition(
                name = credentialScheme.vcType!!,
                schema = SchemaReference(uri = credentialScheme.schemaUri),
            )
        )
        val requestPresentation = RequestCredentialAttachment(
            credentialManifest = credentialManifest,
        )
        val attachment = JwmAttachment.encodeBase64(jsonSerializer.encodeToString(requestPresentation))
        return RequestCredential(
            body = RequestCredentialBody(
                comment = "Please issue some credentials",
                goalCode = "issue-vc-${AriesGoalCodeParser.getAriesName(credentialScheme)}",
                formats = arrayOf(
                    AttachmentFormatReference(
                        attachmentId = attachment.id,
                        format = "dif/credential-manifest@v1.0"
                    )
                )
            ),
            parentThreadId = parentThreadId,
            attachment = attachment
        )
    }

    private suspend fun issueCredential(lastMessage: RequestCredential, senderKey: JsonWebKey): InternalNextMessage {
        val lastJwmAttachment = lastMessage.attachments?.firstOrNull()
            ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-missing")
        val requestCredentialAttachment = lastJwmAttachment.decodeString()?.let {
            RequestCredentialAttachment.deserialize(it).getOrNull()
        } ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-format")

        val uri = requestCredentialAttachment.credentialManifest.credential.schema.uri
        val requestedCredentialScheme = AttributeIndex.resolveSchemaUri(uri)
            ?: return problemReporter.problemLastMessage(lastMessage.threadId, "requested-attributes-empty")

        // TODO Is there a way to transport the format, i.e. JWT-VC or SD-JWT?
        val cryptoPublicKey = requestCredentialAttachment.credentialManifest.subject
            ?.let { kotlin.runCatching { CryptoPublicKey.fromDid(it) }.getOrNull() }
            ?: senderKey.toCryptoPublicKey().getOrNull()
            ?: return problemReporter.problemInternal(lastMessage.threadId, "no-sender-key")
        val issuedCredentials = issuer?.issueCredential(
            subjectPublicKey = cryptoPublicKey,
            credentialScheme = requestedCredentialScheme,
            representation = ConstantIndex.CredentialRepresentation.PLAIN_JWT
        ) ?: return problemReporter.problemInternal(lastMessage.threadId, "credentials-empty")

        //TODO: Pack this info into `args` or `comment`
        val issuedCredential = issuedCredentials.getOrElse {
            //TODO prioritise which descriptors to handle when
            //TODO communicate auth problems too? we have an exception for that now…
            return when {
                it is DataSourceProblem -> it.toProblemRequirement()
                it.cause != null && it.cause is DataSourceProblem -> (it.cause as DataSourceProblem).toProblemRequirement()
                else -> problemReporter.problemInternal(lastMessage.threadId, "credentials-empty")
            }
        }
        val fulfillmentAttachments = mutableListOf<JwmAttachment>()

        when (issuedCredential) {
            is Issuer.IssuedCredential.Iso -> fulfillmentAttachments.add(JwmAttachment.encodeBase64(issuedCredential.issuerSigned.serialize()))
            is Issuer.IssuedCredential.VcJwt -> fulfillmentAttachments.add(JwmAttachment.encodeJws(issuedCredential.vcJws))
            is Issuer.IssuedCredential.VcSdJwt -> fulfillmentAttachments.add(JwmAttachment.encodeJws(issuedCredential.vcSdJwt))
        }

        val message = IssueCredential(
            body = IssueCredentialBody(
                comment = "Here are your credentials",
                formats = fulfillmentAttachments.map {
                    AttachmentFormatReference(
                        attachmentId = it.id,
                        format = "dif/credential-manifest/fulfillment@v1.0"
                    )
                }.toTypedArray()
            ),
            threadId = lastMessage.threadId!!, //is allowed to fail horribly
            attachments = fulfillmentAttachments.toTypedArray()
        )
        return InternalNextMessage.SendAndWrap(message, senderKey)
            .also { this.threadId = message.threadId }
            .also { this.state = State.FINISHED }
    }

    private fun DataSourceProblem.toProblemRequirement() =
        problemReporter.problemRequirement(threadId, "data-source", formatComment())

    private fun DataSourceProblem.formatComment(): String = message + details?.let { ": $it" }

    private suspend fun storeCredentials(lastMessage: IssueCredential): InternalNextMessage {
        val attachmentIdsForFulfillment = lastMessage.body.formats
            .filter { it.format == "dif/credential-manifest/fulfillment@v1.0" }
            .map { it.attachmentId }
        val lastAttachments = lastMessage.attachments
            ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-missing")
        val issueCredentialAttachments = lastAttachments
            .filter { attachmentIdsForFulfillment.contains(it.id) }
        if (issueCredentialAttachments.isEmpty())
            return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-format")
        val credentialList = issueCredentialAttachments
            .mapNotNull { extractFulfillmentAttachment(it) }
            .firstOrNull() ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-format")
        this.result = holder?.storeCredential(credentialList)
            ?: return problemReporter.problemLastMessage(lastMessage.threadId, "no-holder")

        return InternalNextMessage.Finished(lastMessage)
            .also { this.state = State.FINISHED }
    }

    private fun extractFulfillmentAttachment(fulfillment: JwmAttachment): Holder.StoreCredentialInput? {
        runCatching { fulfillment.decodeString() }.getOrNull()?.let { decoded ->
            return Holder.StoreCredentialInput.Vc(decoded, credentialScheme)
        } ?: runCatching { fulfillment.decodeBinary() }.getOrNull()?.let { decoded ->
            IssuerSigned.deserialize(decoded).getOrNull()?.let { issuerSigned ->
                return Holder.StoreCredentialInput.Iso(issuerSigned, credentialScheme)
            }
        } ?: return null
    }

    override fun getResult(): IssueCredentialProtocolResult? {
        return result
    }

    override val isFinished: Boolean
        get() = this.state == State.FINISHED

}
