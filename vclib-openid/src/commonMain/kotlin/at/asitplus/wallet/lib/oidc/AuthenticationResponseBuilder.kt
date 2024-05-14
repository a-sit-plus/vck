package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.SubmissionRequirement
import kotlinx.serialization.Serializable

@Serializable
class AuthenticationResponseBuilder(
    val parameters: AuthenticationRequestParameters,
    val responseType: String,
    val clientMetadata: RelyingPartyMetadata,
    val audience: String,
    val nonce: String,
    val submissionBuilder: PresentationSubmissionBuilder?,
) {
}

@Serializable
class PresentationSubmissionBuilder(
    val presentationDefinitionId: String?,
    val inputDescriptorMatches: Map<InputDescriptor, Collection<HolderAgent.CandidateInputMatchContainer>>,
    val submissionRequirements: Collection<SubmissionRequirement>?,
) {
    val submissionSelection = inputDescriptorMatches.entries.mapNotNull { entry ->
        if(entry.value.isNotEmpty()) {
            entry.key to entry.value.first()
        } else null
    }.toMap().toMutableMap()

    companion object {
        @Suppress("unused")
        suspend fun startPresentationPreparation(
            presentationDefinition: PresentationDefinition,
            fallbackFormatHolder: FormatHolder?,
            pathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean,
            holderAgent: HolderAgent,
        ): KmmResult<AuthenticationResponseBuilder> {
            val matches = holderAgent.matchInputDescriptorsAgainstCredentialStore(
                presentationDefinition = presentationDefinition,
                fallbackFormatHolder = fallbackFormatHolder,
                pathAuthorizationValidator = pathAuthorizationValidator
            ).getOrElse {
                return KmmResult.failure(it)
            }
            return KmmResult.success(
                AuthenticationResponseBuilder(
                    inputDescriptorMatches = matches,
                    submissionRequirements = presentationDefinition.submissionRequirements
                )
            )
        }
    }
}