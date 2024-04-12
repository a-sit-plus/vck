package at.asitplus.wallet.lib.data.JSONPath

import kotlinx.serialization.json.JsonElement


typealias NodeList = List<NodeListEntry>

sealed class SingularQuerySegment {
    class NameSegment(memberName: String) : SingularQuerySegment()
    class IndexSegment(index: Int) : SingularQuerySegment()
}

data class NodeListEntry(
    // can be an integer for index selectors, or a string for member selectors
    val singularQuerySegments: List<JSONPathSelector.SingularQuerySelector>,
    val value: JsonElement,
)