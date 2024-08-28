package at.asitplus.wallet.lib.data.dif

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.InputDescriptor
import at.asitplus.dif.PresentationDefinition
import at.asitplus.dif.SubmissionRequirement
import kotlinx.serialization.Serializable

@Serializable
sealed class PresentationSubmissionValidator {
    companion object {
        fun createInstance(
            submissionRequirements: Collection<SubmissionRequirement>?,
            inputDescriptors: Collection<InputDescriptor>,
        ): KmmResult<PresentationSubmissionValidator> = catching {
            val verifier = submissionRequirements?.let { _ ->
                SubmissionRequirementsValidator(
                    submissionRequirements = submissionRequirements,
                    inputDescriptorGroups = inputDescriptors.associate {
                        it.id to (it.group ?: throw MissingInputDescriptorGroupException(it))
                    },
                )
            } ?: InputDescriptorSubmissionsValidator(
                inputDescriptorIds = inputDescriptors.map { it.id }.toSet()
            )
            return KmmResult.success(verifier)
        }

        fun createInstance(
            presentationDefinition: PresentationDefinition,
        ): KmmResult<PresentationSubmissionValidator> = createInstance(
            submissionRequirements = presentationDefinition.submissionRequirements,
            inputDescriptors = presentationDefinition.inputDescriptors,
        )
    }

    /**
     * Primitive to check, whether all submission requirements are satisfied
     */
    protected abstract fun isSubmissionRequirementsSatisfied(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean

    /**
     * Checks, whether submission requirements are satisfied, and also fails if there are unnecessary submissions
     */
    fun isValidSubmission(
        submittedInputDescriptorIds: Set<String>,
    ): Boolean = isSubmissionRequirementsSatisfied(submittedInputDescriptorIds)
            && findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds).isEmpty()


    fun findUnnecessaryInputDescriptorSubmissions(submittedInputDescriptorIds: Set<String>): Set<String> =
        submittedInputDescriptorIds.filter {
            isSubmissionRequirementsSatisfied(submittedInputDescriptorIds - it)
        }.toSet()

    @Serializable
    data class InputDescriptorSubmissionsValidator(
        val inputDescriptorIds: Set<String>,
    ) : PresentationSubmissionValidator() {
        override fun isSubmissionRequirementsSatisfied(
            submittedInputDescriptorIds: Set<String>,
        ): Boolean = submittedInputDescriptorIds.containsAll(inputDescriptorIds)
    }

    @Serializable
    data class SubmissionRequirementsValidator(
        val submissionRequirements: Collection<SubmissionRequirement>,
        val inputDescriptorGroups: Map<String, String>,
    ) : PresentationSubmissionValidator() {
        override fun isSubmissionRequirementsSatisfied(
            submittedInputDescriptorIds: Set<String>,
        ): Boolean = submissionRequirements.all {
            it.evaluate(
                inputDescriptorGroups = inputDescriptorGroups,
                selectedInputDescriptorIds = submittedInputDescriptorIds,
            )
        }
    }

    class MissingInputDescriptorGroupException(inputDescriptor: InputDescriptor) : Exception(
        "Input descriptor is missing field `group` and is therefore not eligible for use with submission requirements: $inputDescriptor"
    )
}