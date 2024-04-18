package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

typealias NodeList = List<NodeListEntry>
data class NodeListEntry(
    val singularQuerySelectors: List<JSONPathSelector.SingularQuerySelector>,
    val value: JsonElement,
)