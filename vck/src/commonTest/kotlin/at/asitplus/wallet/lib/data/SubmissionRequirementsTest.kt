package at.asitplus.wallet.lib.data

import at.asitplus.dif.SubmissionRequirement
import at.asitplus.dif.SubmissionRequirementRuleEnum
import de.infix.testBalloon.framework.testSuite
import at.asitplus.testballoon.*
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.shouldBe

val SubmissionRequirementsTest by testSuite{
    "all" - {
        "from" - {
            val group = "A"
            val submissionRequirement = SubmissionRequirement(
                rule = SubmissionRequirementRuleEnum.ALL,
                from = group,
            )

            "1" - {
                val inputDescriptorId = "0"

                "inGroup" - {
                    val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                    "selected" - {
                        val selectedInputDescriptorIds = listOf(inputDescriptorId)

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                    "notSelected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }
                }

                "notInGroup" - {
                    val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                    "selected" - {
                        val selectedInputDescriptorIds = listOf(inputDescriptorId)

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                    "notSelected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                }
            }

            "2" - {
                val inputDescriptor0Id = "0"
                val inputDescriptor1Id = "1"

                "bothInGroup" - {
                    val inputDescriptorGroups = mapOf(
                        inputDescriptor0Id to group,
                        inputDescriptor1Id to group,
                    )

                    "bothSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                            inputDescriptor1Id,
                        )

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "secondSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor1Id,
                        )

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }

                    "firstSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                        )

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }

                    "neither selected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }
                }

                "first in group" - {
                    val inputDescriptorGroups = mapOf(
                        inputDescriptor0Id to group,
                        inputDescriptor1Id to (group + "2"),
                    )

                    "both selected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                            inputDescriptor1Id,
                        )

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "firstSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                        )

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "secondSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor1Id,
                        )

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }

                    "neitherSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor1Id,
                        )

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }
                }

                "groups00" - {
                    val actualGroup = group + "2"
                    val inputDescriptorGroups = mapOf(
                        inputDescriptor0Id to actualGroup,
                        inputDescriptor1Id to actualGroup,
                    )

                    "bothSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                            inputDescriptor1Id,
                        )

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "oneSelected" - {
                        val selectionPossibilities = listOf(
                            listOf(inputDescriptor0Id),
                            listOf(inputDescriptor1Id),
                        )

                        "shouldBeTrue" {
                            selectionPossibilities.forEach {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = it
                                ) shouldBe true
                            }
                        }
                    }

                    "neitherSelected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                }

                "groups01" - {
                    val inputDescriptorGroups = mapOf(
                        inputDescriptor0Id to group + "2",
                        inputDescriptor1Id to group + "3",
                    )

                    "bothSelected" - {
                        val selectedInputDescriptorIds = listOf(
                            inputDescriptor0Id,
                            inputDescriptor1Id,
                        )

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "oneSelected" - {
                        val selectionPossibilities = listOf(
                            listOf(inputDescriptor0Id),
                            listOf(inputDescriptor1Id),
                        )

                        "shouldBeTrue" {
                            selectionPossibilities.forEach {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = it
                                ) shouldBe true
                            }
                        }
                    }

                    "neitherSelected" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }
                }
            }
        }

        "nested" - {
            "1" - {
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

                "satisfied" - {
                    val selectedInputDescriptorIds = listOf(inputDescriptorId)

                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "unsatisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }
            }

            "2" - {
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

                "bothSatisfied" - {
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
                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "firstSatisfied" - {
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
                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }

                "secondSatisfied" - {
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
                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }

                "neitherSatisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }
            }
        }
    }

    "pick" - {
        "from" - {
            val group = "A"

            "count" - {
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, from = group, count = 1
                )

                "1" - {
                    val inputDescriptorId = "0"

                    "inGroup" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                        "selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "notSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "notInGroup" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                        "selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                        "notSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }
                }

                "2" - {
                    val inputDescriptor0Id = "0"
                    val inputDescriptor1Id = "1"

                    "bothInGroup" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group,
                            inputDescriptor1Id to group,
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "secondSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "firstSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "groupsT0" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group,
                            inputDescriptor1Id to (group + "2"),
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "firstSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "secondSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "groups00" - {
                        val actualGroup = group + "2"
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to actualGroup,
                            inputDescriptor1Id to actualGroup,
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "oneSelected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "shouldBeFalse" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "groups01" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group + "2",
                            inputDescriptor1Id to group + "3",
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "oneSelected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "shouldBeFalse" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }
                }
            }
            "min" - {
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, from = group, min = 1
                )

                "1" - {
                    val inputDescriptorId = "0"

                    "inGroup" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                        "selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "notSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "notInGroup" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                        "selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                        "notSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }
                }

                "2" - {
                    val inputDescriptor0Id = "0"
                    val inputDescriptor1Id = "1"

                    "bothInGroup" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group,
                            inputDescriptor1Id to group,
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "secondSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "firstSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
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

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
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

                            "shouldBeTrue" {
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

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
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

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "oneSelected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "shouldBeFalse" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }

                    "groups01" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group + "2",
                            inputDescriptor1Id to group + "3",
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "oneSelected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "shouldBeFalse" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe false
                                }
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }
                    }
                }
            }
            "max" - {
                val submissionRequirement = SubmissionRequirement(
                    rule = SubmissionRequirementRuleEnum.PICK, from = group, max = 1
                )

                "1" - {
                    val inputDescriptorId = "0"

                    "inGroup" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group)

                        "selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "notSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                    }

                    "notInGroup" - {
                        val inputDescriptorGroups = mapOf(inputDescriptorId to group + "2")

                        "selected" - {
                            val selectedInputDescriptorIds = listOf(inputDescriptorId)

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                        "notSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                    }
                }

                "2" - {
                    val inputDescriptor0Id = "0"
                    val inputDescriptor1Id = "1"

                    "bothInGroup" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group,
                            inputDescriptor1Id to group,
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeFalse" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe false
                            }
                        }

                        "secondSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "firstSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeTrue" {
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

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
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

                            "shouldBeTrue" {
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

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
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

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "oneSelected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "shouldBeTrue" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe true
                                }
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }
                    }

                    "groups01" - {
                        val inputDescriptorGroups = mapOf(
                            inputDescriptor0Id to group + "2",
                            inputDescriptor1Id to group + "3",
                        )

                        "bothSelected" - {
                            val selectedInputDescriptorIds = listOf(
                                inputDescriptor0Id,
                                inputDescriptor1Id,
                            )

                            "shouldBeTrue" {
                                submissionRequirement.evaluate(
                                    inputDescriptorGroups = inputDescriptorGroups,
                                    selectedInputDescriptorIds = selectedInputDescriptorIds
                                ) shouldBe true
                            }
                        }

                        "oneSelected" - {
                            val selectionPossibilities = listOf(
                                listOf(inputDescriptor0Id),
                                listOf(inputDescriptor1Id),
                            )

                            "shouldBeTrue" {
                                selectionPossibilities.forEach {
                                    submissionRequirement.evaluate(
                                        inputDescriptorGroups = inputDescriptorGroups,
                                        selectedInputDescriptorIds = it
                                    ) shouldBe true
                                }
                            }
                        }

                        "neitherSelected" - {
                            val selectedInputDescriptorIds = listOf<String>()

                            "shouldBeTrue" {
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

        "nested" - {
            "count" - {
                "1" - {
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

                    "isSatisfied" - {
                        val selectedInputDescriptorIds = listOf(inputDescriptorId)

                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe true
                        }
                    }

                    "isNotSatisfied" - {
                        val selectedInputDescriptorIds = listOf<String>()

                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }
                }

                "2" - {
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

                    "bothSatisfied" - {
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
                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds
                            ) shouldBe false
                        }
                    }

                    "firstSatisfied" - {
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
                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe true
                        }
                    }

                    "secondSatisfied" - {
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
                        "shouldBeTrue" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe true
                        }
                    }

                    "neitherSatisfied" - {
                        val selectedInputDescriptorIds = listOf<String>()
                        nestedRequirements[0].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                        nestedRequirements[1].evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                        "shouldBeFalse" {
                            submissionRequirement.evaluate(
                                inputDescriptorGroups = inputDescriptorGroups,
                                selectedInputDescriptorIds = selectedInputDescriptorIds,
                            ) shouldBe false
                        }
                    }
                }
            }
        }
        "min" - {
            "1" - {
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

                "satisfied" - {
                    val selectedInputDescriptorIds = listOf(inputDescriptorId)

                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "isNotSatisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }
            }

            "2" - {
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

                "both satisfied" - {
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
                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "0 is satisfied" - {
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
                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "1 is satisfied" - {
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
                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "neitherSatisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe false
                    }
                }
            }
        }
        "max" - {
            "1" - {
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

                "satisfied" - {
                    val selectedInputDescriptorIds = listOf(inputDescriptorId)

                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }

                "unsatisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()

                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe true
                    }
                }
            }

            "2" - {
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

                "both satisfied" - {
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
                    "shouldBeFalse" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds
                        ) shouldBe false
                    }
                }

                "first satisfied" - {
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
                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "second satisfied" - {
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
                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }

                "neither satisfied" - {
                    val selectedInputDescriptorIds = listOf<String>()
                    nestedRequirements[0].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    nestedRequirements[1].evaluate(
                        inputDescriptorGroups = inputDescriptorGroups,
                        selectedInputDescriptorIds = selectedInputDescriptorIds,
                    ) shouldBe false
                    "shouldBeTrue" {
                        submissionRequirement.evaluate(
                            inputDescriptorGroups = inputDescriptorGroups,
                            selectedInputDescriptorIds = selectedInputDescriptorIds,
                        ) shouldBe true
                    }
                }
            }
        }
    }
}