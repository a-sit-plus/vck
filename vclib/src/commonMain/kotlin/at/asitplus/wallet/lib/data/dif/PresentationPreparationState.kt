package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import kotlinx.serialization.Serializable

@Serializable
data class PresentationPreparationState(
    private var privateInputDescriptorMatches: Map<InputDescriptor, List<HolderAgent.CandidateInputMatchContainer>>,
    val fallbackFormatHolder: FormatHolder? = null,
) {
    val inputDescriptorMatches by ::privateInputDescriptorMatches

    suspend fun refreshInputDescriptorMatches(
        holder: Holder,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
    ) {
        privateInputDescriptorMatches = holder.matchInputDescriptorsAgainstCredentialStore(
            inputDescriptors = inputDescriptorMatches.keys,
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow().mapValues {
            it.value.toList()
        }
    }
}