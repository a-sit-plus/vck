package at.asitplus.jsonpath.core

import kotlinx.serialization.json.JsonElement


internal class JsonPathSelectorQuery(
    private val selectors: List<JsonPathSelector>,
) : JsonPathQuery {
    override fun invoke(currentNode: JsonElement, rootNode: JsonElement): NodeList {
        var matches = selectors.firstOrNull()?.invoke(
            currentNode = currentNode,
            rootNode = rootNode,
        ) ?: listOf()
        selectors.forEachIndexed { index, selector ->
            matches = if(index == 0) matches else matches.flatMap { match ->
                selector.invoke(
                    currentNode = match.value,
                    rootNode = rootNode,
                ).map { newMatch ->
                    NodeListEntry(
                        normalizedJsonPath = match.normalizedJsonPath + newMatch.normalizedJsonPath,
                        value = newMatch.value
                    )
                }
            }
        }
        return matches
    }

    val isSingularQuery: Boolean
        get() = selectors.all { // 2.3.5.1.  Syntax: https://datatracker.ietf.org/doc/rfc9535/
            when(it) {
                JsonPathSelector.RootSelector,
                JsonPathSelector.CurrentNodeSelector,
                is JsonPathSelector.MemberSelector,
                is JsonPathSelector.IndexSelector -> true
                else -> false
            }
        }
}