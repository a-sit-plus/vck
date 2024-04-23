package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.wallet.lib.data.jsonPath.NormalizedJsonPathSegment.IndexSegment
import at.asitplus.wallet.lib.data.jsonPath.NormalizedJsonPathSegment.NameSegment
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.math.max
import kotlin.math.min

/*
https://datatracker.ietf.org/doc/html/rfc7493
https://datatracker.ietf.org/doc/html/rfc9535/
https://datatracker.ietf.org/doc/html/rfc8259
 */

sealed interface JsonPathSelector {
    fun invoke(
        currentNode: JsonElement,
        rootNode: JsonElement = currentNode,
    ): NodeList

    data object RootSelector : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return listOf(
                NodeListEntry(
                    normalizedJsonPath = NormalizedJsonPath(),
                    value = currentNode
                )
            )
        }
    }

    class MemberSelector(val memberName: String) : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> listOf()

                is JsonObject -> listOfNotNull(currentNode[memberName]?.let {
                    NodeListEntry(
                        normalizedJsonPath = NormalizedJsonPath(NameSegment(memberName)),
                        value = it
                    )
                })
            }
        }
    }

    class IndexSelector(val index: Int) : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> {
                    val actualIndex = if (index >= 0) {
                        index
                    } else {
                        index + currentNode.size
                    }
                    listOfNotNull(
                        currentNode.getOrNull(actualIndex)?.let {
                            NodeListEntry(
                                normalizedJsonPath = NormalizedJsonPath(IndexSegment(actualIndex.toUInt())),
                                value = it
                            )
                        }
                    )
                }


                is JsonObject -> listOf()
            }
        }
    }

    data object WildCardSelector : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> currentNode.indices.flatMap {
                    IndexSelector(it).invoke(
                        currentNode = currentNode,
                        rootNode = rootNode,
                    )
                }

                is JsonObject -> currentNode.keys.flatMap {
                    MemberSelector(it).invoke(
                        currentNode = currentNode,
                        rootNode = rootNode,
                    )
                }
            }
        }
    }

    class UnionSelector(val selectors: List<JsonPathSelector>) : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return selectors.flatMap {
                it.invoke(
                    currentNode = currentNode,
                    rootNode = rootNode,
                )
            }
        }
    }

    class SliceSelector(
        val startInclusive: Int? = null,
        val endExclusive: Int? = null,
        val step: Int? = null,
    ) : JsonPathSelector {
        // source: section 2.3.4.2.2 of https://datatracker.ietf.org/doc/rfc9535/
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> {
                    // The default value for step is 1.
                    val actualStepSize = step ?: 1

                    // When step is 0, no elements are selected.
                    if (actualStepSize == 0) {
                        return listOf()
                    }

                    // default start and end according to specification
                    val start = startInclusive
                        ?: if (actualStepSize > 0) 0 else currentNode.size - 1
                    val end = endExclusive
                        ?: if (actualStepSize > 0) currentNode.size else -currentNode.size - 1

                    val (lower, upper) = bounds(start, end, actualStepSize, currentNode.size)

                    val range = if (actualStepSize > 0) {
                        lower..<upper step actualStepSize
                    } else {
                        upper downTo lower + 1 step -actualStepSize
                    }

                    range.flatMap { index ->
                        IndexSelector(index).invoke(
                            currentNode = currentNode,
                            rootNode = rootNode,
                        )
                    }
                }

                is JsonObject -> listOf()
            }
        }

        private fun normalize(index: Int, arrayLength: Int): Int {
            return if (index >= 0) {
                index
            } else {
                arrayLength + index
            }
        }

        private fun bounds(start: Int, end: Int, stepSize: Int, arrayLength: Int): Pair<Int, Int> {
            val normalizedStart = normalize(start, arrayLength)
            val normalizedEnd = normalize(end, arrayLength)

            // implementation bounds according to specification
            return if (stepSize >= 0) {
                val lower = min(max(normalizedStart, 0), arrayLength)
                val upper = min(max(normalizedEnd, 0), arrayLength)
                lower to upper
            } else {
                val upper = min(max(normalizedStart, -1), arrayLength - 1)
                val lower = min(max(normalizedEnd, -1), arrayLength - 1)
                lower to upper
            }
        }
    }

    data object DescendantSelector : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            //  For each i such that 1 <= i <= n, the nodelist Ri is defined to be a
            //   result of applying the child segment [<selectors>] to the node Di.
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> RootSelector.invoke(
                    currentNode = currentNode,
                    rootNode = rootNode,
                ) + currentNode.flatMapIndexed { index, childNode ->
                    invoke(
                        currentNode = childNode,
                        rootNode = rootNode
                    ).map {
                        NodeListEntry(
                            normalizedJsonPath = NormalizedJsonPath(IndexSegment(index.toUInt())) + it.normalizedJsonPath,
                            it.value
                        )
                    }
                }

                is JsonObject -> RootSelector.invoke(
                    currentNode = currentNode,
                    rootNode = rootNode,
                ) + currentNode.flatMap { entry ->
                    invoke(entry.value, rootNode).map {
                        NodeListEntry(
                            normalizedJsonPath = NormalizedJsonPath(NameSegment(entry.key)) + it.normalizedJsonPath,
                            it.value
                        )
                    }
                }
            }
        }
    }

    class FilterSelector(
        private val filterPredicate: FilterPredicate,
    ) : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> currentNode.flatMapIndexed { index, it ->
                    IndexSelector(index).invoke(
                        currentNode = currentNode,
                        rootNode = rootNode,
                    )
                }

                is JsonObject -> currentNode.entries.flatMap {
                    MemberSelector(it.key).invoke(
                        currentNode = currentNode,
                        rootNode = rootNode,
                    )
                }
            }.filter {
                filterPredicate.invoke(
                    currentNode = it.value,
                    rootNode = rootNode,
                )
            }
        }
    }
}

interface FilterPredicate {
    fun invoke(
        currentNode: JsonElement,
        rootNode: JsonElement,
    ): Boolean
}