package at.asitplus.wallet.lib.aries

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4


class PresentProofMessenger private constructor(
    private val holder: Holder? = null,
    private val verifier: Verifier? = null,
    messageWrapper: MessageWrapper,
    private val serviceEndpoint: String? = null,
    private val challengeForPresentation: String = uuid4().toString(),
    createProtocolWhenNotActive: Boolean = true,
    private val requestedAttributeTypes: Collection<String>? = null,
    private val credentialScheme: ConstantIndex.CredentialScheme,
) : ProtocolMessenger<PresentProofProtocol, PresentProofProtocolResult>(
    messageWrapper = messageWrapper,
    createProtocolWhenNotActive = createProtocolWhenNotActive,
    signInitialMessage = true,
    signFollowingMessages = true,
    signAndEncryptFollowingMessages = true
) {

    override fun createProtocolInstance() = PresentProofProtocol(
        verifier = verifier,
        holder = holder,
        requestedAttributeTypes = requestedAttributeTypes,
        credentialScheme = credentialScheme,
        serviceEndpoint = serviceEndpoint,
        challengeForPresentation = challengeForPresentation,
    )

    companion object {
        /**
         * Creates a new instance of this messenger for the Holder side,
         * it will create the Verifiable Presentation
         */
        fun newHolderInstance(
            holder: Holder,
            messageWrapper: MessageWrapper,
            serviceEndpoint: String,
            credentialScheme: ConstantIndex.CredentialScheme,
        ) = PresentProofMessenger(
            holder = holder,
            messageWrapper = messageWrapper,
            serviceEndpoint = serviceEndpoint,
            credentialScheme = credentialScheme,
        )

        /**
         * Creates a new instance of this messenger for the Verifier side,
         * it will request the Verifiable Presentation and validate it
         */
        fun newVerifierInstance(
            verifier: Verifier,
            messageWrapper: MessageWrapper,
            credentialScheme: ConstantIndex.CredentialScheme,
            requestedAttributeTypes: Collection<String>? = null,
            challengeForPresentation: String = uuid4().toString()
        ) = PresentProofMessenger(
            verifier = verifier,
            messageWrapper = messageWrapper,
            requestedAttributeTypes = requestedAttributeTypes,
            credentialScheme = credentialScheme,
            challengeForPresentation = challengeForPresentation,
        )
    }
}
