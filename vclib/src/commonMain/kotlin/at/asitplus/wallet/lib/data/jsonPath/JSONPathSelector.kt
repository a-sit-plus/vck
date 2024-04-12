package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.math.max
import kotlin.math.min

/*
https://datatracker.ietf.org/doc/html/rfc7493
https://datatracker.ietf.org/doc/rfc9535/
https://datatracker.ietf.org/doc/html/rfc8259
 */

fun JsonElement.matchJsonPath(
    jsonPath: String
): NodeList {
    var matches = listOf(
        NodeListEntry(
            singularQuerySelectors = listOf(),
            value = this,
        )
    )
    JSONPathToJSONPathSelectorListCompiler().compile(jsonPath)?.forEach { selector ->
        matches = matches.flatMap { match ->
            selector.invoke(
                rootNode = this,
                currentNode = match.value
            ).map { newMatch ->
                NodeListEntry(
                    singularQuerySelectors = match.singularQuerySelectors + newMatch.singularQuerySelectors,
                    value = newMatch.value
                )
            }
        }
    }
    return matches
}

sealed interface JSONPathSelector {
    fun invoke(
        rootNode: JsonElement,
        currentNode: JsonElement,
    ): NodeList

    class RootSelector : JSONPathSelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return listOf(
                NodeListEntry(
                    singularQuerySelectors = listOf(),
                    value = currentNode
                )
            )
        }
    }

    class WildCardSelector : JSONPathSelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> currentNode.mapIndexed { index, it ->
                    NodeListEntry(
                        singularQuerySelectors = listOf(IndexSelector(index)),
                        value = it,
                    )
                }

                is JsonObject -> currentNode.entries.map {
                    NodeListEntry(
                        singularQuerySelectors = listOf(MemberSelector(it.key)),
                        value = it.value,
                    )
                }
            }
        }
    }

    sealed interface SingularQuerySelector : JSONPathSelector
    class MemberSelector(val memberName: String) : SingularQuerySelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> listOf()

                is JsonObject -> listOfNotNull(currentNode[memberName]?.let {
                    NodeListEntry(
                        singularQuerySelectors = listOf(MemberSelector(memberName)),
                        value = it
                    )
                })
            }
        }
    }

    class IndexSelector(val index: Int) : SingularQuerySelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> listOfNotNull(
                    currentNode.getOrNull(index)?.let {
                        NodeListEntry(
                            singularQuerySelectors = listOf(IndexSelector(index)),
                            value = it
                        )
                    }
                )


                is JsonObject -> listOf()
            }
        }
    }

    class UnionSelector(
        val selectors: List<JSONPathSelector>
    ) : JSONPathSelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return selectors.map {
                it.invoke(
                    rootNode = rootNode,
                    currentNode = currentNode,
                )
            }.flatten()
        }
    }

    class SliceSelector(
        val startInclusive: Int? = null,
        val endExclusive: Int? = null,
        val step: Int? = null
    ) : JSONPathSelector {
        // source: section 2.3.4.2.2 of https://datatracker.ietf.org/doc/rfc9535/
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> {
                    // The default value for step is 1.
                    val actualStepSize = step ?: 1

                    // When step is 0, no elements are selected.
                    if (actualStepSize == 0) return listOf()

                    // default start and end according to specification
                    val start = startInclusive
                        ?: if (actualStepSize > 0) 0 else currentNode.size - 1
                    val end = endExclusive
                        ?: if (actualStepSize > 0) currentNode.size else -currentNode.size - 1

                    val (lower, upper) = bounds(start, end, actualStepSize, currentNode.size)

                    val range = if (actualStepSize > 0) {
                        lower..<upper step actualStepSize
                    } else {
                        upper downTo lower + 1 step actualStepSize
                    }

                    range.map { index ->
                        currentNode.getOrNull(index)
                    }.filterNotNull().mapIndexed { index, it ->
                        NodeListEntry(
                            singularQuerySelectors = listOf(IndexSelector(index)),
                            value = it
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

    class DescendantSelector() : JSONPathSelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> listOf(
                    NodeListEntry(
                        singularQuerySelectors = listOf(),
                        value = currentNode
                    )
                ) + currentNode.mapIndexed { index, it ->
                    NodeListEntry(
                        singularQuerySelectors = listOf(IndexSelector(index)),
                        value = it
                    )
                }

                is JsonObject -> listOf()
            }
        }
    }

    class FilterSelector(
        val ctx: JSONPathParser.LogicalExprContext,
        val functionExtensions: Map<String, FunctionExtensionEvaluator>,
    ) : JSONPathSelector {
        override fun invoke(
            rootNode: JsonElement,
            currentNode: JsonElement,
        ): NodeList {
            return when (currentNode) {
                is JsonPrimitive -> listOf()

                is JsonArray -> currentNode.mapIndexed { index, it ->
                    NodeListEntry(
                        singularQuerySelectors = listOf(IndexSelector(index)),
                        value = it
                    )
                }

                is JsonObject -> currentNode.entries.map {
                    NodeListEntry(
                        singularQuerySelectors = listOf(MemberSelector(it.key)),
                        value = it.value
                    )
                }
            }.filter {
                JSONPathLogicalFilterExpressionEvaluator(
                    rootNode = rootNode,
                    currentNode = it.value,
                    functionExtensions = functionExtensions,
                ).visitLogicalExpr(
                    ctx
                )
            }
        }
    }
}