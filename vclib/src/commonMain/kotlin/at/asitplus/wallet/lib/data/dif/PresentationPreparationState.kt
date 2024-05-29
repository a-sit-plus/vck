package at.asitplus.wallet.lib.data.dif

import at.asitplus.jsonpath.core.NodeList
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.Serializable

@Serializable
data class PresentationPreparationState(
    val presentationDefinitionId: String?,
    val presentationSubmissionValidator: PresentationSubmissionValidator,
    private var privateInputDescriptorMatches: Map<InputDescriptor, Map<SubjectCredentialStore.StoreEntry, Map<ConstraintField, NodeList>>>,
    val fallbackFormatHolder: FormatHolder? = null,
) {
    val inputDescriptorMatches by ::privateInputDescriptorMatches

    @Throws(PresentationSubmissionValidator.MissingInputDescriptorGroupException::class)
    constructor(
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder? = null,
    ) : this(
        presentationDefinitionId = presentationDefinition.id,
        presentationSubmissionValidator = PresentationSubmissionValidator.createInstance(
            submissionRequirements = presentationDefinition.submissionRequirements,
            inputDescriptors = presentationDefinition.inputDescriptors,
        ).getOrThrow(),
        privateInputDescriptorMatches = presentationDefinition.inputDescriptors.associateWith {
            mapOf() // need to run refreshPresentationPreparationState after initialization
        },
        fallbackFormatHolder = presentationDefinition.formats ?: fallbackFormatHolder,
    )

    suspend fun refreshInputDescriptorMatches(
        holder: Holder,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
    ) {
        privateInputDescriptorMatches = holder.matchInputDescriptorsAgainstCredentialStore(
            inputDescriptors = inputDescriptorMatches.keys,
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow()
    }
}