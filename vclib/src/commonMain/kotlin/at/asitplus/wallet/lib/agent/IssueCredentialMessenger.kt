package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.ConstantIndex


class IssueCredentialMessenger private constructor(
    private val issuer: Issuer? = null,
    private val holder: Holder? = null,
    messageWrapper: MessageWrapper,
    private val serviceEndpoint: String = "https://example.com/",
    createProtocolWhenNotActive: Boolean = true,
    private val credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic
) : ProtocolMessenger<IssueCredentialProtocol, IssueCredentialProtocolResult>(
    messageWrapper = messageWrapper,
    createProtocolWhenNotActive = createProtocolWhenNotActive,
    signInitialMessage = true,
    signFollowingMessages = true,
    signAndEncryptFollowingMessages = false
) {

    override fun createProtocolInstance() = IssueCredentialProtocol(
        issuer = issuer,
        holder = holder,
        serviceEndpoint = serviceEndpoint,
        credentialScheme = credentialScheme,
    )

    companion object {
        /**
         * Creates a new instance of this messenger for the Holder side,
         * it will receive the Verifiable Credentials and validate them.
         */
        fun newHolderInstance(
            holder: Holder,
            messageWrapper: MessageWrapper,
            credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic,
        ) = IssueCredentialMessenger(
            holder = holder,
            messageWrapper = messageWrapper,
            credentialScheme = credentialScheme,
        )

        /**
         * Creates a new instance of this messenger for the Issuer side,
         * it will issue the Verifiable Credentials.
         */
        fun newIssuerInstance(
            issuer: Issuer,
            messageWrapper: MessageWrapper,
            serviceEndpoint: String,
            credentialScheme: ConstantIndex.CredentialScheme = ConstantIndex.Generic,
        ) = IssueCredentialMessenger(
            issuer = issuer,
            messageWrapper = messageWrapper,
            serviceEndpoint = serviceEndpoint,
            credentialScheme = credentialScheme,
        )
    }
}
