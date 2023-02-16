package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4


class PresentProofMessenger private constructor(
    private val holder: Holder? = null,
    private val verifier: Verifier? = null,
    private val keyId: String,
    messageWrapper: MessageWrapper,
    private val serviceEndpoint: String? = null,
    private val challengeForPresentation: String = uuid4().toString(),
    createProtocolWhenNotActive: Boolean = true,
    private val requestedAttributeNames: List<String>? = null,
    private val credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic
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
        requestedAttributeNames = requestedAttributeNames,
        credentialScheme = credentialScheme,
        keyId = keyId,
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
            keyId: String,
            messageWrapper: MessageWrapper,
            serviceEndpoint: String,
            credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic,
        ) = PresentProofMessenger(
            holder = holder,
            keyId = keyId,
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
            keyId: String,
            messageWrapper: MessageWrapper,
            credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic,
            requestedAttributeNames: List<String>? = null,
            challengeForPresentation: String = uuid4().toString()
        ) = PresentProofMessenger(
            verifier = verifier,
            keyId = keyId,
            messageWrapper = messageWrapper,
            requestedAttributeNames = requestedAttributeNames,
            credentialScheme = credentialScheme,
            challengeForPresentation = challengeForPresentation,
        )
    }
}
