package at.asitplus.wallet.lib.data.dif

import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.PathAuthorizationValidator
import kotlinx.serialization.Serializable

@Serializable
class PresentationSubmissionBuilder(
    val presentationDefinition: PresentationDefinition,
    val fallbackFormatHolder: FormatHolder? = null,
) {
    private var _inputDescriptorMatches = mapOf<InputDescriptor, List<HolderAgent.CandidateInputMatchContainer>>()
    val inputDescriptorMatches by ::_inputDescriptorMatches

    /**
     * Selection is a map from string to int,
     * where the string indicates the input descriptor id,
     * and the int indicates the index of the credential in the current matching list
     *
     * This is done because the builder should survive serialization and re-parsing.
     * If this would be a mapping from InputDescriptor to CandidateInputMatchContainer,
     * then serialization and reparsing would result in a submission selection,
     * where the keys are not elements if the inputDescriptorMatches list.
     */
    lateinit var submissionSelection: MutableMap<String, UInt>
    init {
        resetSubmissionSelection()
    }

    fun isValid(): Boolean = if (presentationDefinition.submissionRequirements == null) {
        inputDescriptorMatches.keys.all {
            // making sure, that all input descriptors are selected
            submissionSelection.containsKey(it.id)
        } and submissionSelection.entries.all { selection ->
            // making sure, that all the indices are still in range
            inputDescriptorMatches.entries.firstOrNull {
                it.key.id == selection.key
            }?.let { inputDescriptorMatches ->
                inputDescriptorMatches.value.lastIndex.toUInt() >= selection.value
            } ?: false
        }
    } else {
        val currentSubmissionSelection = submissionSelection.entries.mapNotNull { selection ->
            inputDescriptorMatches.entries.first { entry ->
                entry.key.id == selection.key
            }.let { entry ->
                entry.value.getOrNull(selection.value.toInt())?.let {
                    entry.key to it
                }
            }
        }.toMap()
        presentationDefinition.submissionRequirements.all {
            it.evaluate(
                inputDescriptors = inputDescriptorMatches.keys,
                submissionSelection = currentSubmissionSelection,
            )
        }
    }

    suspend fun refreshInputDescriptors(
        holder: Holder, pathAuthorizationValidator: PathAuthorizationValidator?
    ) {
        _inputDescriptorMatches = holder.matchInputDescriptorsAgainstCredentialStore(
            inputDescriptors = presentationDefinition.inputDescriptors,
            fallbackFormatHolder = presentationDefinition.formats ?: fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow().mapValues {
            it.value.toList()
        }
        resetSubmissionSelection()
    }

    private fun resetSubmissionSelection() {
        // select the first credential from all the descriptor matches by default (if existing)
        submissionSelection = inputDescriptorMatches.entries.mapNotNull { entry ->
            if (entry.value.isNotEmpty()) {
                entry.key.id to 0u
            } else null
        }.toMap().toMutableMap()
    }
}

fun SubmissionRequirement.evaluate(
    inputDescriptors: Collection<InputDescriptor>,
    submissionSelection: Map<InputDescriptor, HolderAgent.CandidateInputMatchContainer>,
): Boolean {
    return when (rule) {
        SubmissionRequirementRuleEnum.ALL -> when {
            from != null -> inputDescriptors.filter {
                it.group == from
            }.all {
                submissionSelection.keys.contains(it)
            }

            fromNested != null -> fromNested.all {
                it.evaluate(
                    inputDescriptors = inputDescriptors,
                    submissionSelection = submissionSelection,
                )
            }

            else -> throw SubmissionRequirementsStructureException(
                "neither `from` nor `fromNested` have been provided"
            )
        }

        SubmissionRequirementRuleEnum.PICK -> when {
            from != null -> inputDescriptors.filter {
                it.group == from
            }.count {
                submissionSelection.keys.contains(it)
            }

            fromNested != null -> fromNested.map {
                it.evaluate(
                    inputDescriptors = inputDescriptors,
                    submissionSelection = submissionSelection,
                )
            }.count {
                it
            }

            else -> throw SubmissionRequirementsStructureException(
                "neither `from` nor `fromNested` have been provided"
            )
        }.let { selected ->
            listOf(
                this.count?.let { selected == it } ?: true,
                this.min?.let { selected >= it } ?: true,
                this.count?.let { selected <= it } ?: true,
            ).all {
                it
            }
        }

        else -> throw SubmissionRequirementsStructureException(
            "invalid rule: ${rule?.text}"
        )
    }
}

class SubmissionRequirementsStructureException(message: String) : Exception(message)