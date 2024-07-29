package at.asitplus.wallet.lib.data.dif

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Data class for
 * [DIF Presentation Exchange v1.0.0](https://identity.foundation/presentation-exchange/spec/v1.0.0/#presentation-definition)
 */
@Serializable
data class SubmissionRequirement(
    @SerialName("name")
    val name: String? = null,
    @SerialName("purpose")
    val purpose: String? = null,
    @SerialName("rule")
    val rule: SubmissionRequirementRuleEnum? = null,
    @SerialName("count")
    val count: Int? = null,
    @SerialName("min")
    val min: Int? = null,
    @SerialName("max")
    val max: Int? = null,
    @SerialName("from")
    val from: String? = null,
    @SerialName("from_nested")
    val fromNested: Collection<SubmissionRequirement>? = null,
) {
    /**
     * Evaluating submission requirements as per [Presentation Exchange 2.0.0 - Submission Requirement Rules](https://identity.foundation/presentation-exchange/spec/v2.0.0/#submission-requirement-rules).
     *
     * @param inputDescriptorGroups: a mapping from input descriptor id to the group of the input descriptor
     * @param selectedInputDescriptorIds: a set of input descriptor ids for which a credential is submitted
     */
    fun evaluate(
        inputDescriptorGroups: Map<String, String>,
        selectedInputDescriptorIds: Collection<String>,
    ): Boolean = when (rule) {
        SubmissionRequirementRuleEnum.ALL -> when {
            from != null -> inputDescriptorGroups.filter {
                it.value == from
            }.all {
                selectedInputDescriptorIds.contains(it.key)
            }

            fromNested != null -> fromNested.all {
                it.evaluate(
                    inputDescriptorGroups = inputDescriptorGroups,
                    selectedInputDescriptorIds = selectedInputDescriptorIds,
                )
            }

            else -> throw SubmissionRequirementsStructureException(
                "neither `from` nor `fromNested` have been provided"
            )
        }

        SubmissionRequirementRuleEnum.PICK -> when {
            from != null -> inputDescriptorGroups.filter {
                it.value == from
            }.count {
                selectedInputDescriptorIds.contains(it.key)
            }

            fromNested != null -> fromNested.map {
                it.evaluate(
                    inputDescriptorGroups = inputDescriptorGroups,
                    selectedInputDescriptorIds = selectedInputDescriptorIds,
                )
            }.count {
                it
            }

            else -> throw SubmissionRequirementsStructureException(
                "neither `from` nor `fromNested` have been provided"
            )
        }.let { numSelected ->
            listOfNotNull(
                this.count?.let { numSelected == it },
                this.min?.let { numSelected >= it },
                this.max?.let { numSelected <= it },
            ).all {
                it
            }
        }

        else -> throw SubmissionRequirementsStructureException(
            "invalid rule: ${rule?.text}"
        )
    }


    class SubmissionRequirementsStructureException(message: String) : Exception(message)
}