package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import kotlinx.serialization.Serializable

/**
 * Container for preparing submissions, even when serialization and deserialization is required while preparation
 */
@Serializable
class PresentationPreparationHelper(
    val presentationDefinitionId: String?,
    val submissionRequirements: Collection<SubmissionRequirement>?,
    private var privateInputDescriptorMatches: Map<InputDescriptor, List<HolderAgent.CandidateInputMatchContainer>>,
    val fallbackFormatHolder: FormatHolder? = null,
) {
    constructor(
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder? = null,
    ) : this(
        presentationDefinitionId = presentationDefinition.id,
        submissionRequirements = presentationDefinition.submissionRequirements,
        privateInputDescriptorMatches = presentationDefinition.inputDescriptors.associateWith {
            // need to run a refresh against the credential store after initialization
            listOf<HolderAgent.CandidateInputMatchContainer>()
        },
        fallbackFormatHolder = presentationDefinition.formats ?: fallbackFormatHolder,
    )

    val inputDescriptorMatches by ::privateInputDescriptorMatches
    val inputDescriptorGroups: Map<String, String>
        get() = inputDescriptorMatches.keys.associate {
            it.id to it.group!! // group is checked at code point:7fe1e939-913c-47c9-9309-1e0d3ea39a9c
        }

    init {
        if(submissionRequirements != null) {
            inputDescriptorMatches.entries.forEach {
                if (it.key.group == null) {
                    // code point:7fe1e939-913c-47c9-9309-1e0d3ea39a9c
                    throw MissingInputDescriptorGroupException(it.key)
                }
            }
        }
    }

    suspend fun refreshInputDescriptorMatches(
        holder: Holder,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) {
        privateInputDescriptorMatches = holder.matchInputDescriptorsAgainstCredentialStore(
            inputDescriptors = inputDescriptorMatches.keys,
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow().mapValues {
            it.value.toList()
        }
    }

    fun isSubmissionRequirementsSatisfied(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean {
        return if (!isSubmissionRequirementListSatisfied(submittedInputDescriptorIds)) {
            false
        } else {
            // do not allow submissions for unnecessary input descriptors
            findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds).isEmpty()
        }
    }

    fun findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds: Set<String>): Set<String> {
        return submittedInputDescriptorIds.filter {
            isSubmissionRequirementListSatisfied(submittedInputDescriptorIds - it)
        }.toSet()
    }

    private fun isSubmissionRequirementListSatisfied(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean = submissionRequirements?.all {
        it.evaluate(
            inputDescriptorGroups = inputDescriptorMatches.keys.associate {
                it.id to it.group!! // group is checked at code point:7fe1e939-913c-47c9-9309-1e0d3ea39a9c
            },
            selectedInputDescriptorIds = submittedInputDescriptorIds,
        )
    } ?: run {
        // default submission requirement is, that a credential is submitted for each input descriptor
        inputDescriptorMatches.keys.map { it.id }.toSet() == submittedInputDescriptorIds
    }
}

open class InvalidInputDescriptorForSubmissionRequirementsException(message: String) :
    Exception(message)

open class MissingInputDescriptorGroupException(inputDescriptor: InputDescriptor) :
    InvalidInputDescriptorForSubmissionRequirementsException(
        "Input descriptor is missing field `group` and therefore does not satisfy requirements for use with submission requirements: $inputDescriptor"
    )