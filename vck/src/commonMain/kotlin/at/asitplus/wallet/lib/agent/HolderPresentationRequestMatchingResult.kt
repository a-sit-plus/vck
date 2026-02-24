package at.asitplus.wallet.lib.agent

interface HolderPresentationRequestMatchingResult<Credential: Any> {
    val credentials: List<Credential>
}