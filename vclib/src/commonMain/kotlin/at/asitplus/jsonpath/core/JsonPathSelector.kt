package at.asitplus.jsonpath.core

import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.IndexSegment
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment.NameSegment
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.math.max
import kotlin.math.min

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.3.  Selectors
 */
internal sealed interface JsonPathSelector {
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
                    value = rootNode
                )
            )
        }
    }

    data object CurrentNodeSelector : JsonPathSelector {
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

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.3.1.  Name Selector
     */
    data class MemberSelector(val memberName: String) : JsonPathSelector {
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

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.3.3.  Index Selector
     */
    data class IndexSelector(val index: Int) : JsonPathSelector {
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

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.3.2.  Wildcard Selector
     */
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
    
    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.3.2.  Wildcard Selector
     */
    data class BracketedSelector(val selectors: List<JsonPathSelector>) : JsonPathSelector {
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

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.3.4.  Array Slice Selector
     */
    data class SliceSelector(
        val startInclusive: Int? = null,
        val endExclusive: Int? = null,
        val step: Int? = null,
    ) : JsonPathSelector {
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

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.5.2.  Descendant Segment
     */
    data class DescendantSelector(
        val selector: JsonPathSelector,
    ) : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            //  For each i such that 1 <= i <= n, the nodelist Ri is defined to be a
            //   result of applying the child segment [<selectors>] to the node Di.
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> CurrentNodeSelector.invoke(
                    currentNode = currentNode,
                    rootNode = rootNode,
                ).flatMap { descendant ->
                    selector.invoke(
                        currentNode = descendant.value,
                        rootNode = rootNode,
                    ).map {
                        NodeListEntry(
                            normalizedJsonPath = descendant.normalizedJsonPath + it.normalizedJsonPath,
                            value = it.value,
                        )
                    }
                } + currentNode.flatMapIndexed { index, childNode ->
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

                is JsonObject -> CurrentNodeSelector.invoke(
                    currentNode = currentNode,
                    rootNode = rootNode,
                ).flatMap { descendant ->
                    selector.invoke(
                        currentNode = descendant.value,
                        rootNode = rootNode,
                    ).map {
                        NodeListEntry(
                            normalizedJsonPath = descendant.normalizedJsonPath + it.normalizedJsonPath,
                            value = it.value,
                        )
                    }
                } + currentNode.flatMap { entry ->
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

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section: 2.3.5.  Filter Selector
     */
    data class FilterSelector(
        private val filterPredicate: FilterPredicate,
    ) : JsonPathSelector {
        override fun invoke(
            currentNode: JsonElement,
            rootNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> currentNode.flatMapIndexed { index, _ ->
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