package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

class JsonPathQuery(
    val selectors: List<JsonPathSelector>,
) {
    fun invoke(currentNode: JsonElement, rootNode: JsonElement = currentNode): NodeList {
        var matches = listOf(
            NodeListEntry(
                normalizedJsonPath = NormalizedJsonPath(),
                value = currentNode,
            )
        )
        selectors.forEach { selector ->
            matches = matches.flatMap { match ->
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
        get() = selectors.all {
            when(it) {
                JsonPathSelector.RootSelector,
                is JsonPathSelector.MemberSelector,
                is JsonPathSelector.IndexSelector -> true
                else -> false
            }
        }
}