package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

class JsonPathQuery(
    val selectors: List<JsonPathSelector>,
) {
    fun invoke(currentNode: JsonElement, rootNode: JsonElement = currentNode): NodeList {
        var matches = listOf(
            NodeListEntry(
                singularQuerySelectors = listOf(),
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
                        singularQuerySelectors = match.singularQuerySelectors + newMatch.singularQuerySelectors,
                        value = newMatch.value
                    )
                }
            }
        }
        return matches
    }

    val isSingularQuery: Boolean
        get() = selectors.filter {
            it !is JsonPathSelector.RootSelector
        }.all {
            it is JsonPathSelector.SingularQuerySelector
        }
}