@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.openid

@Deprecated(
    "Moved to at.asitplus.wallet.lib.agent",
    ReplaceWith("CredentialMatchingResult<Credential>", "at.asitplus.wallet.lib.agent.CredentialMatchingResult"),
)
typealias CredentialMatchingResult<Credential> = at.asitplus.wallet.lib.agent.CredentialMatchingResult<Credential>

@Deprecated(
    "Moved to at.asitplus.wallet.lib.agent",
    ReplaceWith("PresentationExchangeMatchingResult<Credential>", "at.asitplus.wallet.lib.agent.PresentationExchangeMatchingResult"),
)
typealias PresentationExchangeMatchingResult<Credential> =
        at.asitplus.wallet.lib.agent.PresentationExchangeMatchingResult<Credential>

@Deprecated(
    "Moved to at.asitplus.wallet.lib.agent",
    ReplaceWith("DCQLMatchingResult<Credential>", "at.asitplus.wallet.lib.agent.DCQLMatchingResult"),
)
typealias DCQLMatchingResult<Credential> = at.asitplus.wallet.lib.agent.DCQLMatchingResult<Credential>

@Deprecated(
    "Moved to at.asitplus.wallet.lib.agent",
    ReplaceWith("IsoDeviceRetrievalMatchingResult<Credential>", "at.asitplus.wallet.lib.agent.IsoDeviceRetrievalMatchingResult"),
)
typealias IsoDeviceRetrievalMatchingResult<Credential> =
        at.asitplus.wallet.lib.agent.IsoDeviceRetrievalMatchingResult<Credential>
