package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

typealias NodeList = List<NodeListEntry>

data class NodeListEntry(
    val normalizedJsonPath: NormalizedJsonPath,
    val value: JsonElement,
)
