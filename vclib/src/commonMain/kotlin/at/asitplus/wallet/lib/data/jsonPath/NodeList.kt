package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement


typealias NodeList = List<NodeListEntry>

data class NodeListEntry(
    // can be an integer for index selectors, or a string for member selectors
    val singularQuerySelectors: List<JSONPathSelector.SingularQuerySelector>,
    val value: JsonElement,
)