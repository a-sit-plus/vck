package at.asitplus.jsonpath.implementation

import kotlinx.serialization.json.JsonElement

internal data class JsonPathExpressionEvaluationContext(
    val currentNode: JsonElement,
    val rootNode: JsonElement = currentNode,
)