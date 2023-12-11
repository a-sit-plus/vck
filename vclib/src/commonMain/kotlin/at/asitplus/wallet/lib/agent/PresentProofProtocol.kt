package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.msg.RequestPresentationAttachment
import at.asitplus.wallet.lib.msg.RequestPresentationAttachmentOptions
import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.msg.SchemaReference
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.FormatContainerJwt
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.jsonSerializer
import at.asitplus.wallet.lib.msg.AttachmentFormatReference
import at.asitplus.wallet.lib.msg.JsonWebMessage
import at.asitplus.wallet.lib.msg.JwmAttachment
import at.asitplus.wallet.lib.msg.OutOfBandInvitation
import at.asitplus.wallet.lib.msg.OutOfBandInvitationBody
import at.asitplus.wallet.lib.msg.OutOfBandService
import at.asitplus.wallet.lib.msg.Presentation
import at.asitplus.wallet.lib.msg.PresentationBody
import at.asitplus.wallet.lib.msg.RequestPresentation
import at.asitplus.wallet.lib.msg.RequestPresentationBody
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.serialization.encodeToString

typealias PresentProofProtocolResult = Verifier.VerifyPresentationResult

/**
 * Use this class for exactly one instance of a protocol run.
 *
 * Implements a trimmed-down version of
 * [ARIES RFC 0454 Present Proof V2](https://github.com/hyperledger/aries-rfcs/tree/main/features/0454-present-proof-v2)
 * and uses
 * [DIF Presentation Exchange](https://identity.foundation/presentation-exchange/)
 * for
 * [attachments](https://github.com/hyperledger/aries-rfcs/tree/main/features/0510-dif-pres-exch-attach).
 *
 * The [verifier] requests a Verifiable Presentation, and the [holder] fulfills this request.
 *
 * If [verifier] is passed as `null`, no verification of the received presentation happens.
 */
class PresentProofProtocol(
    private val holder: Holder? = null,
    private val verifier: Verifier? = null,
    private val requestedAttributeNames: List<String>? = null,
    private val credentialScheme: ConstantIndex.CredentialScheme,
    private val keyId: String,
    private val serviceEndpoint: String?,
    private val challengeForPresentation: String,
) : ProtocolStateMachine<PresentProofProtocolResult> {

    companion object {
        /**
         * Creates a new instance of this protocol for the Holder side,
         * it will create the Verifiable Presentation
         */
        fun newHolderInstance(
            holder: Holder,
            keyId: String,
            serviceEndpoint: String,
            credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic,
        ) = PresentProofProtocol(
            holder = holder,
            credentialScheme = credentialScheme,
            keyId = keyId,
            serviceEndpoint = serviceEndpoint,
            challengeForPresentation = uuid4().toString(),
        )

        /**
         * Creates a new instance of this protocol for the Verifier side,
         * it will request the Verifiable Presentation and validate it
         */
        fun newVerifierInstance(
            verifier: Verifier,
            keyId: String,
            serviceEndpoint: String? = null,
            credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic,
            requestedAttributeNames: List<String>? = null,
        ) = PresentProofProtocol(
            verifier = verifier,
            requestedAttributeNames = requestedAttributeNames,
            credentialScheme = credentialScheme,
            keyId = keyId,
            serviceEndpoint = serviceEndpoint,
            challengeForPresentation = uuid4().toString()
        )
    }

    private var result: PresentProofProtocolResult? = null
    private val problemReporter = ProblemReporter()
    private var state: State = State.START
    private var invitationId: String? = null
    private var threadId: String? = null

    enum class State {
        START,
        INVITATION_SENT,
        REQUEST_PRESENTATION_SENT,
        FINISHED
    }

    override fun startCreatingInvitation(): InternalNextMessage {
        if (this.state != State.START)
            return InternalNextMessage.IncorrectState("state")
                .also { Napier.w("Unexpected state: $state") }
        Napier.d("Start PresentProofProtocol with oobInvitation")
        return createOobInvitation()
    }

    override fun startDirect(): InternalNextMessage {
        if (this.state != State.START)
            return InternalNextMessage.IncorrectState("state")
                .also { Napier.w("Unexpected state: $state") }
        Napier.d("Start PresentProofProtocol with requestPresentation")
        return createRequestPresentation()
    }

    override suspend fun parseMessage(
        body: JsonWebMessage,
        senderKeyId: String
    ): InternalNextMessage {
        when (this.state) {
            State.START -> {
                if (body is OutOfBandInvitation)
                    return createRequestPresentation(body, senderKeyId)
                if (body is RequestPresentation)
                    return createPresentation(body, senderKeyId)
                return InternalNextMessage.IncorrectState("messageType")
                    .also { Napier.w("Unexpected messageType: ${body.type}") }
            }
            State.INVITATION_SENT -> {
                if (body !is RequestPresentation)
                    return InternalNextMessage.IncorrectState("messageType")
                        .also { Napier.w("Unexpected messageType: ${body.type}") }
                if (body.parentThreadId != invitationId)
                    return InternalNextMessage.IncorrectState("parentThreadId")
                        .also { Napier.w("Unexpected parentThreadId: ${body.parentThreadId}") }
                return createPresentation(body, senderKeyId)
            }
            State.REQUEST_PRESENTATION_SENT -> {
                if (body !is Presentation)
                    return InternalNextMessage.IncorrectState("messageType")
                        .also { Napier.w("Unexpected messageType: ${body.type}") }
                if (body.threadId != threadId)
                    return InternalNextMessage.IncorrectState("threadId")
                        .also { Napier.w("Unexpected threadId: ${body.threadId}") }
                return verifyPresentation(body)
            }
            else -> return InternalNextMessage.IncorrectState("state")
                .also { Napier.w("Unexpected state: $state") }
        }
    }

    private fun createOobInvitation(): InternalNextMessage {
        val message = OutOfBandInvitation(
            body = OutOfBandInvitationBody(
                handshakeProtocols = arrayOf(SchemaIndex.PROT_PRESENT_PROOF),
                acceptTypes = arrayOf("application/didcomm-encrypted+json"),
                goalCode = credentialScheme.goalCodeRequestProof,
                services = arrayOf(
                    OutOfBandService(
                        type = "did-communication",
                        recipientKeys = arrayOf(keyId),
                        serviceEndpoint = serviceEndpoint ?: "https://example.com",
                    )
                ),
            )
        )
        return InternalNextMessage.SendAndWrap(message)
            .also { this.invitationId = message.id }
            .also { this.state = State.INVITATION_SENT }
    }

    private fun createRequestPresentation(): InternalNextMessage {
        val message = buildRequestPresentationMessage(credentialScheme, null)
        return InternalNextMessage.SendAndWrap(message)
            .also { this.threadId = message.threadId }
            .also { this.state = State.REQUEST_PRESENTATION_SENT }
    }

    private fun createRequestPresentation(
        invitation: OutOfBandInvitation,
        senderKeyId: String
    ): InternalNextMessage {
        val credentialScheme = ConstantIndex.Parser.parseGoalCode(invitation.body.goalCode)
            ?: return problemReporter.problemLastMessage(invitation.threadId, "goal-code-unknown")
        val message = buildRequestPresentationMessage(credentialScheme, invitation.id)
        val serviceEndpoint = invitation.body.services?.let {
            if (it.isNotEmpty()) it[0].serviceEndpoint else null
        }
        return InternalNextMessage.SendAndWrap(message, senderKeyId, serviceEndpoint)
            .also { this.threadId = message.threadId }
            .also { this.state = State.REQUEST_PRESENTATION_SENT }
    }

    private fun buildRequestPresentationMessage(
        credentialScheme: ConstantIndex.CredentialScheme,
        parentThreadId: String? = null,
    ): RequestPresentation {
        val constraintsNames =
            requestedAttributeNames?.map(this::buildConstraintFieldForName) ?: listOf()
        val constraintsTypes = buildConstraintFieldForType(credentialScheme.vcType)
        val presentationDefinition = PresentationDefinition(
            inputDescriptors = arrayOf(
                InputDescriptor(
                    name = credentialScheme.credentialDefinitionName,
                    schema = SchemaReference(uri = credentialScheme.schemaUri),
                    constraints = Constraint(
                        fields = (constraintsNames + constraintsTypes).toTypedArray()
                    )
                )
            ),
            formats = FormatHolder(
                jwtVp = FormatContainerJwt(arrayOf("ES256"))
            )
        )
        val requestPresentation = RequestPresentationAttachment(
            presentationDefinition = presentationDefinition,
            options = RequestPresentationAttachmentOptions(
                challenge = challengeForPresentation,
                verifier = keyId
            )
        )
        val attachment =
            JwmAttachment.encodeBase64(jsonSerializer.encodeToString(requestPresentation))
        return RequestPresentation(
            body = RequestPresentationBody(
                comment = "Please show your credentials",
                formats = arrayOf(
                    AttachmentFormatReference(
                        attachmentId = attachment.id,
                        format = "dif/presentation-exchange/definitions@v1.0"
                    )
                )
            ),
            parentThreadId = parentThreadId,
            attachment = attachment
        )
    }

    private fun buildConstraintFieldForName(attributeName: String) = ConstraintField(
        path = arrayOf("\$.vc[*].credentialSubject[*].name", "\$.credentialSubject[*].name"),
        filter = ConstraintFilter(type = "string", const = attributeName)
    )

    private fun buildConstraintFieldForType(attributeType: String) = ConstraintField(
        path = arrayOf("\$.vc[*].type", "\$.type"),
        filter = ConstraintFilter(type = "string", const = attributeType)
    )

    private suspend fun createPresentation(
        lastMessage: RequestPresentation,
        senderKeyId: String
    ): InternalNextMessage {
        val attachments = lastMessage.attachments
            ?: return problemReporter.problemLastMessage(
                lastMessage.threadId,
                "attachments-missing"
            )
        val jwmAttachment = attachments[0]
        val requestPresentationAttachment = jwmAttachment.decodeString()?.let {
            RequestPresentationAttachment.deserialize(it)
        } ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-format")
        val requestedTypes = requestPresentationAttachment.presentationDefinition.inputDescriptors
            .mapNotNull { it.constraints }
            .flatMap { it.fields?.toList() ?: listOf() }
            .filter { it.path.contains("\$.vc[*].type") }
            .mapNotNull { it.filter }
            .filter { it.type == "string" }
            .mapNotNull { it.const }
        val requestedFields = requestPresentationAttachment.presentationDefinition.inputDescriptors
            .mapNotNull { it.constraints }
            .flatMap { it.fields?.toList() ?: listOf() }
            .filter { it.path.contains("\$.vc[*].credentialSubject[*].name") }
            .mapNotNull { it.filter }
            .filter { it.type == "string" }
            .mapNotNull { it.const }
        val vp = holder?.createPresentation(
            requestPresentationAttachment.options.challenge,
            requestPresentationAttachment.options.verifier ?: senderKeyId,
            attributeTypes = requestedTypes.ifEmpty { null },
            attributeNames = requestedFields.ifEmpty { null }
        ) ?: return problemReporter.problemInternal(lastMessage.threadId, "vp-empty")
        if (vp !is Holder.CreatePresentationResult.Signed) {
            return problemReporter.problemInternal(lastMessage.threadId, "vp-not-signed")
        }
        val attachment = JwmAttachment.encodeJws(vp.jws)
        val message = Presentation(
            body = PresentationBody(
                comment = "Please show your credentials",
                formats = arrayOf(
                    AttachmentFormatReference(
                        attachmentId = attachment.id,
                        format = "dif/presentation-exchange/definitions@v1.0"
                    )
                )
            ),
            threadId = lastMessage.threadId!!,
            attachment = attachment
        )
        return InternalNextMessage.SendAndWrap(message, senderKeyId)
            .also { this.threadId = message.threadId }
            .also { this.state = State.FINISHED }
    }

    private fun verifyPresentation(lastMessage: Presentation): InternalNextMessage {
        val attachments = lastMessage.attachments
            ?: return problemReporter.problemLastMessage(
                lastMessage.threadId,
                "attachments-missing"
            )
        val jwmAttachment = attachments[0]
        val presentationAttachment = jwmAttachment.decodeString()
            ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-format")

        this.result = verifier?.verifyPresentation(presentationAttachment, challengeForPresentation)
            ?: Verifier.VerifyPresentationResult.NotVerified(
                presentationAttachment,
                challengeForPresentation
            )

        return InternalNextMessage.Finished(lastMessage)
            .also { this.state = State.FINISHED }
    }

    override fun getResult(): PresentProofProtocolResult? {
        return result
    }

    override val isFinished: Boolean
        get() = this.state == State.FINISHED

}
