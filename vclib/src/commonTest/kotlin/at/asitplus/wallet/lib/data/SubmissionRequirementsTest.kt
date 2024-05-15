package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.dif.SubmissionRequirement
import at.asitplus.wallet.lib.data.dif.SubmissionRequirementRuleEnum
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

class SubmissionRequirementsTest : FreeSpec({
    "given select all from group requirement" - {
        val group = "A"
        val submissionRequirement = SubmissionRequirement(
            rule = SubmissionRequirementRuleEnum.ALL,
            from = group,
        )

        "given only 1 descriptor" - {
            val inputDescriptorId = "0"

            "when descriptor is in group" - {
                val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                "then requirement should be satisfied" {
                    submissionRequirement.evaluate(
                        inputDescriptorIdsToGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = listOf(inputDescriptorId)
                    ) shouldBe true
                }
            }

            "when descriptor is not in group" - {
                val inputDescriptorGroups = mapOf(inputDescriptorId to (group + "a"))

                "then requirement should not be satisfied" {
                    submissionRequirement.evaluate(
                        inputDescriptorIdsToGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = listOf(inputDescriptorId)
                    ) shouldBe false
                }
            }
        }

        "given 2 descriptors" - {
            val inputDescriptor0Id = "0"
            val inputDescriptor1Id = "1"

            "when both descriptors are in group" - {
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to group,
                    inputDescriptor1Id to group,
                )

                "when both descriptors are selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when descriptor 0 is not selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor1Id,
                    )

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }

                "when descriptor 1 is not selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                    )

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }

                "when neither descriptor is selected" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }
            }

            "when descriptors are in different groups, but descriptor 0 is in the selected group" - {
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to group,
                    inputDescriptor1Id to (group + "2"),
                )

                "when both descriptors are selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when only the descriptor in the intended group is selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                    )

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when only the descriptor not in the intended group is selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor1Id,
                    )

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }

                "when neither descriptor is selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor1Id,
                    )

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }
            }

            "when descriptors are in same groups, but the group is not the intended one" - {
                val actualGroup = group + "2"
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to actualGroup,
                    inputDescriptor1Id to actualGroup,
                )

                "when both descriptors are selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when only one input descriptor is selected" - {
                    val selectionPossibilities = listOf(
                        listOf(inputDescriptor0Id),
                        listOf(inputDescriptor1Id),
                    )

                    "then requirement should be satisfied" {
                        selectionPossibilities.forEach {
                            submissionRequirement.evaluate(
                                inputDescriptorIdsToGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = it
                            ) shouldBe true
                        }
                    }
                }

                "when neither descriptor is selected" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }
            }

            "when descriptors are in different groups, but neither of them is the intended one" - {
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to group + "2",
                    inputDescriptor1Id to group + "3",
                )

                "when both descriptors are selected" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when only one input descriptor is selected" - {
                    val selectionPossibilities = listOf(
                        listOf(inputDescriptor0Id),
                        listOf(inputDescriptor1Id),
                    )

                    "then requirement should be satisfied" {
                        selectionPossibilities.forEach {
                            submissionRequirement.evaluate(
                                inputDescriptorIdsToGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = it
                            ) shouldBe true
                        }
                    }
                }

                "when neither descriptor is selected" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorIdsToGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }
            }
        }
    }
})