package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.dif.SubmissionRequirement
import at.asitplus.wallet.lib.data.dif.SubmissionRequirementRuleEnum
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

@Suppress("unused")
class SubmissionRequirementsTest : FreeSpec({
    "given select all" - {
        "given select from group" - {
            val group = "A"
            val submissionRequirement = SubmissionRequirement(
                rule = SubmissionRequirementRuleEnum.ALL,
                from = group,
            )

            "given 1 descriptor" - {
                val inputDescriptorId = "0"

                "when descriptor is in group" - {
                    val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                    "when descriptor is selected" - {
                        val selectedInputDescriptorIds = listOf(inputDescriptorId)

                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                    "when descriptor is not selected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "then requirement should not be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }
                }

                "when descriptor is not in group" - {
                    val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                    "when descriptor is selected" - {
                        val selectedInputDescriptorIds = listOf(inputDescriptorId)

                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                    "when descriptor is not selected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }

                    "when neither descriptor is selected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "then requirement should not be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = it
                                ) shouldBe true
                            }
                        }
                    }

                    "when neither descriptor is selected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = it
                                ) shouldBe true
                            }
                        }
                    }

                    "when neither descriptor is selected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                }
            }
        }

        "given select from nested" - {
            "given 1 nested requirement" - {
                val nestedGroup = "A"
                val inputDescriptorId = "0"
                val inputDescriptorGroups = mapOf(inputDescriptorId to nestedGroup)
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.ALL,
                    fromNested = listOf(
                        SubmissionRequirement(
                            rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup
                        )
                    ),
                )

                "when nested requirement is satisfied" - {
                    val selectedInputDescriptorIds = listOf(inputDescriptorId)

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when nested requirement is not satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }
            }

            "given 2 nested requirements" - {
                val nestedGroup0 = "A"
                val nestedGroup1 = "B"
                val inputDescriptor0Id = "0"
                val inputDescriptor1Id = "1"
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to nestedGroup0,
                    inputDescriptor1Id to nestedGroup1,
                )

                val nestedRequirements = listOf(
                    SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup0
                    ),
                    SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup1
                    ),
                )
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.ALL,
                    fromNested = nestedRequirements,
                )

                "when both nested requirements are satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    nestedRequirements.forEach {
                        it.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when only first nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                    )
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe true
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }

                "when only second nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor1Id,
                    )
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe true
                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }

                "when neither nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }
            }
        }
    }

    "given select pick" - {
        "given select from group" - {
            val group = "A"

            "given pick count requirement" - {
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, from = group, count = 1
                )

                "given 1 descriptor" - {
                    val inputDescriptorId = "0"

                    "when descriptor is in group" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                        "when descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "when descriptor is not selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "when descriptor is not in group" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                        "when descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                        "when descriptor is not selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
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

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "when descriptor 0 is not selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when descriptor 1 is not selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "when only one input descriptor is selected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "then requirement should not be satisfied" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
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

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "when only one input descriptor is selected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "then requirement should not be satisfied" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }
                }
            }
            "given pick min requirement" - {
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, from = group, min = 1
                )

                "given 1 descriptor" - {
                    val inputDescriptorId = "0"

                    "when descriptor is in group" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                        "when descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "when descriptor is not selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "when descriptor is not in group" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                        "when descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                        "when descriptor is not selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
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
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when descriptor 0 is not selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when descriptor 1 is not selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "when only one input descriptor is selected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "then requirement should not be satisfied" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
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

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "when only one input descriptor is selected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "then requirement should not be satisfied" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }
                }
            }
            "given pick max requirement" - {
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, from = group, max = 1
                )

                "given 1 descriptor" - {
                    val inputDescriptorId = "0"

                    "when descriptor is in group" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                        "when descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "when descriptor is not selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                    }

                    "when descriptor is not in group" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                        "when descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "when descriptor is not selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
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

                            "then requirement should not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "when descriptor 0 is not selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when descriptor 1 is not selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when only the descriptor not in the intended group is selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe true
                                }
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement not be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                    inputDescriptorGroups = inputDescriptorGroups,
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
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe true
                                }
                            }
                        }

                        "when neither descriptor is selected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "then requirement should be satisfied" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                    }
                }
            }
        }

        "given select from nested" - {
            "given pick count requirement" - {
                "given 1 nested requirement" - {
                    val nestedGroup = "A"
                    val inputDescriptorId = "0"
                    val inputDescriptorGroups = mapOf(inputDescriptorId to nestedGroup)
                    val submissionRequirement = SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.PICK, fromNested = listOf(
                            SubmissionRequirement(
                                rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup
                            )
                        ), count = 1
                    )

                    "when nested requirement is satisfied" - {
                        val selectedInputDescriptorIds = listOf(inputDescriptorId)

                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "when nested requirement is not satisfied" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "then requirement should not be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }
                }

                "given 2 nested requirements" - {
                    val nestedGroup0 = "A"
                    val nestedGroup1 = "B"
                    val inputDescriptor0Id = "0"
                    val inputDescriptor1Id = "1"
                    val inputDescriptorGroups = mapOf(
                        inputDescriptor0Id to nestedGroup0,
                        inputDescriptor1Id to nestedGroup1,
                    )

                    val nestedRequirements = listOf(
                        SubmissionRequirement(
                            rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup0
                        ),
                        SubmissionRequirement(
                            rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup1
                        ),
                    )
                    val submissionRequirement = SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.PICK,
                        fromNested = nestedRequirements,
                        count = 1
                    )

                    "when both nested requirements are satisfied" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                            inputDescriptor1Id,
                        )

                        nestedRequirements.forEach {
                            it.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe true
                        }
                        "then requirement should not be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }

                    "when only first nested requirements is satisfied" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                        )
                        nestedRequirements[0].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                        nestedRequirements[1].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe true
                        }
                    }

                    "when only second nested requirements is satisfied" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor1Id,
                        )
                        nestedRequirements[0].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                        nestedRequirements[1].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                        "then requirement should be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe true
                        }
                    }

                    "when neither nested requirements is satisfied" - {
                        val selectedInputDescriptorIds = listOf<String>()
                        nestedRequirements[0].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                        nestedRequirements[1].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                        "then requirement should not be satisfied" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe false
                        }
                    }
                }
            }
        }
        "given pick min requirement" - {
            "given 1 nested requirement" - {
                val nestedGroup = "A"
                val inputDescriptorId = "0"
                val inputDescriptorGroups = mapOf(inputDescriptorId to nestedGroup)
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, fromNested = listOf(
                        SubmissionRequirement(
                            rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup
                        )
                    ), min = 1
                )

                "when nested requirement is satisfied" - {
                    val selectedInputDescriptorIds = listOf(inputDescriptorId)

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when nested requirement is not satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }
            }

            "given 2 nested requirements" - {
                val nestedGroup0 = "A"
                val nestedGroup1 = "B"
                val inputDescriptor0Id = "0"
                val inputDescriptor1Id = "1"
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to nestedGroup0,
                    inputDescriptor1Id to nestedGroup1,
                )

                val nestedRequirements = listOf(
                    SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup0
                    ),
                    SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup1
                    ),
                )
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK,
                    fromNested = nestedRequirements,
                    min = 1
                )

                "when both nested requirements are satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    nestedRequirements.forEach {
                        it.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when only first nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                    )
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe true
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "when only second nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor1Id,
                    )
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe true
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "when neither nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }
            }
        }
        "given pick max requirement" - {
            "given 1 nested requirement" - {
                val nestedGroup = "A"
                val inputDescriptorId = "0"
                val inputDescriptorGroups = mapOf(inputDescriptorId to nestedGroup)
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, fromNested = listOf(
                        SubmissionRequirement(
                            rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup
                        )
                    ), max = 1
                )

                "when nested requirement is satisfied" - {
                    val selectedInputDescriptorIds = listOf(inputDescriptorId)

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "when nested requirement is not satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }
            }

            "given 2 nested requirements" - {
                val nestedGroup0 = "A"
                val nestedGroup1 = "B"
                val inputDescriptor0Id = "0"
                val inputDescriptor1Id = "1"
                val inputDescriptorGroups = mapOf(
                    inputDescriptor0Id to nestedGroup0,
                    inputDescriptor1Id to nestedGroup1,
                )

                val nestedRequirements = listOf(
                    SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup0
                    ),
                    SubmissionRequirement(
                        rule = SubmissionRequirementRuleEnum.ALL, from = nestedGroup1
                    ),
                )
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK,
                    fromNested = nestedRequirements,
                    max = 1
                )

                "when both nested requirements are satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                        inputDescriptor1Id,
                    )

                    nestedRequirements.forEach {
                        it.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                    "then requirement should not be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }

                "when only first nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor0Id,
                    )
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe true
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "when only second nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf(
                        inputDescriptor1Id,
                    )
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe true
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "when neither nested requirements is satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "then requirement should be satisfied" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }
            }
        }
    }
})