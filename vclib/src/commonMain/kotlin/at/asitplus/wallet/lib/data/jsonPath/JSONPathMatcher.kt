package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

interface JSONPathMatcher {
    fun match(jsonElement: JsonElement): NodeList

    val isSingularQuery: Boolean
}

class SimpleJSONPathMatcher(
    val selectors: List<JSONPathSelector>,
): JSONPathMatcher {
    override fun match(jsonElement: JsonElement): NodeList {
        var matches = listOf(
            NodeListEntry(
                normalizedPath = listOf(),
                value = jsonElement,
            )
        )
        selectors.forEach { selector ->
            matches = matches.flatMap { match ->
                selector.invoke(
                    rootNode = jsonElement,
                    currentNode = match.value
                ).map { newMatch ->
                    NodeListEntry(
                        normalizedPath = match.normalizedPath + newMatch.normalizedPath,
                        value = newMatch.value
                    )
                }
            }
        }
        return matches
    }

    override val isSingularQuery: Boolean
        get() = selectors.filter {
            it !is JSONPathSelector.RootSelector
        }.all {
            it is JSONPathSelector.SingularQuerySelector
        }
}