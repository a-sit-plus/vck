package at.asitplus.wallet.lib.aries

import at.asitplus.crypto.datatypes.jws.JsonWebKey
import at.asitplus.crypto.datatypes.jws.JwsAlgorithm
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.AriesGoalCodeParser
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.SchemaIndex
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.FormatContainerJwt
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.msg.AttachmentFormatReference
import at.asitplus.wallet.lib.msg.JsonWebMessage
import at.asitplus.wallet.lib.msg.JwmAttachment
import at.asitplus.wallet.lib.msg.OutOfBandInvitation
import at.asitplus.wallet.lib.msg.OutOfBandInvitationBody
import at.asitplus.wallet.lib.msg.OutOfBandService
import at.asitplus.wallet.lib.msg.Presentation
import at.asitplus.wallet.lib.msg.PresentationBody
import at.asitplus.wallet.lib.msg.RequestPresentation
import at.asitplus.wallet.lib.msg.RequestPresentationAttachment
import at.asitplus.wallet.lib.msg.RequestPresentationAttachmentOptions
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
    private val requestedClaims: Collection<String>? = null,
    private val credentialScheme: ConstantIndex.CredentialScheme,
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
            serviceEndpoint: String,
            credentialScheme: ConstantIndex.CredentialScheme,
        ) = PresentProofProtocol(
            holder = holder,
            credentialScheme = credentialScheme,
            serviceEndpoint = serviceEndpoint,
            challengeForPresentation = uuid4().toString(),
        )

        /**
         * Creates a new instance of this protocol for the Verifier side,
         * it will request the Verifiable Presentation and validate it
         */
        fun newVerifierInstance(
            verifier: Verifier,
            serviceEndpoint: String? = null,
            credentialScheme: ConstantIndex.CredentialScheme,
            requestedClaims: Collection<String>? = null,
        ) = PresentProofProtocol(
            verifier = verifier,
            requestedClaims = requestedClaims,
            credentialScheme = credentialScheme,
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
        senderKey: JsonWebKey
    ): InternalNextMessage {
        when (this.state) {
            State.START -> {
                if (body is OutOfBandInvitation)
                    return createRequestPresentation(body, senderKey)
                if (body is RequestPresentation)
                    return createPresentation(body, senderKey)
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
                return createPresentation(body, senderKey)
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
        val recipientKey = holder?.identifier
            ?: return InternalNextMessage.IncorrectState("holder")
        val message = OutOfBandInvitation(
            body = OutOfBandInvitationBody(
                handshakeProtocols = arrayOf(SchemaIndex.PROT_PRESENT_PROOF),
                acceptTypes = arrayOf("application/didcomm-encrypted+json"),
                goalCode = "request-proof-${AriesGoalCodeParser.getAriesName(credentialScheme)}",
                services = arrayOf(
                    OutOfBandService(
                        type = "did-communication",
                        recipientKeys = arrayOf(recipientKey),
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
            ?: return InternalNextMessage.IncorrectState("verifier")
        return InternalNextMessage.SendAndWrap(message)
            .also { this.threadId = message.threadId }
            .also { this.state = State.REQUEST_PRESENTATION_SENT }
    }

    private fun createRequestPresentation(
        invitation: OutOfBandInvitation,
        senderKey: JsonWebKey
    ): InternalNextMessage {
        val credentialScheme = AriesGoalCodeParser.parseGoalCode(invitation.body.goalCode)
            ?: return problemReporter.problemLastMessage(invitation.threadId, "goal-code-unknown")
        val message = buildRequestPresentationMessage(credentialScheme, invitation.id)
            ?: return InternalNextMessage.IncorrectState("verifier")
        val serviceEndpoint = invitation.body.services?.let {
            if (it.isNotEmpty()) it[0].serviceEndpoint else null
        }
        return InternalNextMessage.SendAndWrap(message, senderKey, serviceEndpoint)
            .also { this.threadId = message.threadId }
            .also { this.state = State.REQUEST_PRESENTATION_SENT }
    }

    private fun buildRequestPresentationMessage(
        credentialScheme: ConstantIndex.CredentialScheme,
        parentThreadId: String? = null,
    ): RequestPresentation? {
        val verifierIdentifier = verifier?.identifier
            ?: return null
        val claimsConstraints = requestedClaims?.map(this::buildConstraintFieldForClaim) ?: listOf()
        val typeConstraints = buildConstraintFieldForType(credentialScheme.vcType!!)
        val presentationDefinition = PresentationDefinition(
            inputDescriptors = listOf(
                InputDescriptor(
                    name = credentialScheme.vcType!!,
                    schema = SchemaReference(uri = credentialScheme.schemaUri),
                    constraints = Constraint(
                        fields = claimsConstraints + typeConstraints
                    )
                )
            ),
            formats = FormatHolder(
                jwtVp = FormatContainerJwt(listOf(JwsAlgorithm.ES256.identifier))
            )
        )
        val requestPresentation = RequestPresentationAttachment(
            presentationDefinition = presentationDefinition,
            options = RequestPresentationAttachmentOptions(
                challenge = challengeForPresentation,
                verifier = verifierIdentifier,
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

    private fun buildConstraintFieldForType(attributeType: String) = ConstraintField(
        path = listOf("\$.vc[*].type", "\$.type"),
        filter = ConstraintFilter(type = "string", const = attributeType)
    )

    private fun buildConstraintFieldForClaim(claimName: String) = ConstraintField(
        path = listOf("\$.vc[*].name", "\$.type"),
        filter = ConstraintFilter(type = "string", const = claimName)
    )

    private suspend fun createPresentation(
        lastMessage: RequestPresentation,
        senderKey: JsonWebKey
    ): InternalNextMessage {
        val attachments = lastMessage.attachments
            ?: return problemReporter.problemLastMessage(
                lastMessage.threadId,
                "attachments-missing"
            )
        val jwmAttachment = attachments[0]
        val requestPresentationAttachment = jwmAttachment.decodeString()?.let {
            RequestPresentationAttachment.deserialize(it).getOrNull()
        } ?: return problemReporter.problemLastMessage(lastMessage.threadId, "attachments-format")
        // TODO Is ISO supported here?
        val presentationResult = holder?.createPresentation(
            challenge = requestPresentationAttachment.options.challenge,
            audienceId = requestPresentationAttachment.options.verifier ?: senderKey.identifier,
            presentationDefinition = requestPresentationAttachment.presentationDefinition,
        )?.getOrNull() ?: return problemReporter.problemInternal(lastMessage.threadId, "vp-empty")
        val vp = presentationResult.presentationResults.firstOrNull()
        // TODO is ISO supported here?
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
        return InternalNextMessage.SendAndWrap(message, senderKey)
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