package at.asitplus.jsonpath.core

import kotlinx.serialization.json.JsonElement

interface JsonPathQuery {
    fun invoke(currentNode: JsonElement, rootNode: JsonElement = currentNode): NodeList
}