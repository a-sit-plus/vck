package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import kotlinx.serialization.Serializable

@Serializable
sealed interface PresentationRequirementsVerifier {
    companion object {
        fun createInstance(
            submissionRequirements: Collection<SubmissionRequirement>?,
            inputDescriptors: Collection<InputDescriptor>,
        ): KmmResult<PresentationRequirementsVerifier> {
            return KmmResult.success(
                submissionRequirements?.let { _ ->
                    SubmissionRequirementsVerifier(
                        submissionRequirements = submissionRequirements,
                        inputDescriptorGroups = inputDescriptors.associate {
                            it.id to (it.group ?: return KmmResult.failure(
                                MissingInputDescriptorGroupException(it)
                            ))
                        },
                    )
                } ?: InputDescriptorSubmissionsVerifier(
                    inputDescriptorIds = inputDescriptors.map { it.id }.toSet()
                )
            )
        }
    }

    @Serializable
    data class InputDescriptorSubmissionsVerifier(
        val inputDescriptorIds: Set<String>,
    ) : PresentationRequirementsVerifier {
        override fun isSubmissionRequirementsSatisfied(
            submittedInputDescriptorIds: Set<String>,
        ): Boolean {
            // default submission requirement is, that a credential is submitted for each input descriptor
            return inputDescriptorIds == submittedInputDescriptorIds
        }
    }

    @Serializable
    data class SubmissionRequirementsVerifier(
        val submissionRequirements: Collection<SubmissionRequirement>,
        val inputDescriptorGroups: Map<String, String>,
    ) : PresentationRequirementsVerifier {
        override fun isSubmissionRequirementsSatisfied(
            submittedInputDescriptorIds: Set<String>,
        ): Boolean {
            return submissionRequirements.all {
                it.evaluate(
                    inputDescriptorGroups = inputDescriptorGroups,
                    selectedInputDescriptorIds = submittedInputDescriptorIds,
                )
            }
        }
    }

    fun isSubmissionRequirementsSatisfied(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean
}

class MissingInputDescriptorGroupException(inputDescriptor: InputDescriptor) : Exception(
    "Input descriptor is missing field `group` and therefore is not eligible for use with submission requirements: $inputDescriptor"
)