package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import kotlinx.serialization.Serializable

/**
 * Container for preparing submissions, even when serialization and deserialization is required while preparation
 */
@Serializable
data class PresentationPreparationHelper(
    val presentationDefinitionId: String?,
    val presentationPreparationState: PresentationPreparationState,
    val presentationSubmissionValidator: PresentationSubmissionValidator,
) {
    @Throws(PresentationSubmissionValidator.MissingInputDescriptorGroupException::class) constructor (
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder? = null,
    ) : this(
        presentationDefinitionId = presentationDefinition.id,
        presentationPreparationState = PresentationPreparationState(
            privateInputDescriptorMatches = presentationDefinition.inputDescriptors.associateWith {
                listOf() // need to run a refreshPresentationPreparationState after initialization
            },
            fallbackFormatHolder = presentationDefinition.formats ?: fallbackFormatHolder,
        ),
        presentationSubmissionValidator = PresentationSubmissionValidator.createInstance(
            submissionRequirements = presentationDefinition.submissionRequirements,
            inputDescriptors = presentationDefinition.inputDescriptors,
        ).getOrThrow(),
    )

    suspend fun refreshPresentationPreparationState(
        holder: Holder,
        pathAuthorizationValidator: PathAuthorizationValidator? = null,
    ) {
        presentationPreparationState.refreshInputDescriptorMatches(
            holder = holder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    fun isValidSubmission(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean {
        return if (!presentationSubmissionValidator.isSubmissionRequirementsSatisfied(
                submittedInputDescriptorIds
            )
        ) {
            false
        } else {
            // do not allow submissions for unnecessary input descriptors
            findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds).isEmpty()
        }
    }

    fun findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds: Set<String>): Set<String> {
        return submittedInputDescriptorIds.filter {
            presentationSubmissionValidator.isSubmissionRequirementsSatisfied(
                submittedInputDescriptorIds - it
            )
        }.toSet()
    }
}
