package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import kotlinx.serialization.Serializable

/**
 * Container for preparing submissions, even when serialization and deserialization is required while preparation
 */
@Serializable
class PresentationSelectionValidator(
    val presentationDefinition: PresentationDefinition,
    val fallbackFormatHolder: FormatHolder? = null,
) {
    private var _inputDescriptorMatches =
        mapOf<InputDescriptor, List<HolderAgent.CandidateInputMatchContainer>>()
    val inputDescriptorMatches by ::_inputDescriptorMatches

    private val inputDescriptorGroups: Map<String, String>
        get() = inputDescriptorMatches.keys.associate {
            it.id to it.group!! // group is checked at code point:7fe1e939-913c-47c9-9309-1e0d3ea39a9c
        }

    fun isSubmissionRequirementsSatisfied(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean {
        return if (!isSubmissionRequirementsSatisfied(submittedInputDescriptorIds)) {
            false
        } else {
            findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds).isEmpty()
        }
    }

    private fun isSubmissionRequirementListSatisfied(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean = if (presentationDefinition.submissionRequirements == null) {
        // default submission requirement is, that a credential is submitted for each input descriptor
        inputDescriptorMatches.keys.map {
            it.id
        }.let {
            it.containsAll(submittedInputDescriptorIds) and submittedInputDescriptorIds.containsAll(
                it
            )
        }
    } else {
        presentationDefinition.submissionRequirements.all {
            it.evaluate(
                inputDescriptorIdsToGroups = inputDescriptorGroups,
                selectedInputDescriptorIds = submittedInputDescriptorIds,
            )
        }
    }

    fun findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds: Set<String>): Set<String> {
        return submittedInputDescriptorIds.filter {
            isSubmissionRequirementListSatisfied(submittedInputDescriptorIds - it)
        }.toSet()
    }

    suspend fun refreshInputDescriptors(
        holder: Holder,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) {
        _inputDescriptorMatches = holder.matchInputDescriptorsAgainstCredentialStore(
            inputDescriptors = presentationDefinition.inputDescriptors,
            fallbackFormatHolder = presentationDefinition.formats ?: fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow().mapValues {
            it.value.toList()
        }

        inputDescriptorMatches.entries.forEach {
            if (it.key.group == null) {
                // code point:7fe1e939-913c-47c9-9309-1e0d3ea39a9c
                throw MissingInputDescriptorGroupException(it.key)
            }
        }

        // when the input descriptors are re-evaluated, then the submission selection needs to be reset
        // - its's hard to correlate between the previous selection and the new selection
        resetSubmissionSelection()
    }

    fun resetSubmissionSelection() {
        // select the first credential from all the descriptor matches by default (if existing)
        submissionSelection = inputDescriptorMatches.entries.mapNotNull { entry ->
            if (entry.value.isNotEmpty()) {
                entry.key.id to 0u
            } else null
        }.toMap().toMutableMap()
    }
}

class InvalidSubmissionSelectionException(message: String) : Exception(message)

open class InvalidInputDescriptorForSubmissionRequirementsException(message: String) :
    Exception(message)

open class MissingInputDescriptorGroupException(inputDescriptor: InputDescriptor) :
    InvalidInputDescriptorForSubmissionRequirementsException(
        "Input descriptor is missing field `group` and therefore does not satisfy requirements for use with submission requirements: $inputDescriptor"
    )