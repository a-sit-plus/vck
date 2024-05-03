package at.asitplus.jsonpath

import at.asitplus.jsonpath.core.JsonPathFunctionExtension

/**
 * This class is not specified in the rfc standard, it's but an implementation detail.
 * It's a way to provide users with a way to add custom function extensions.
 */
interface JsonPathFunctionExtensionRepository {
    fun addExtension(functionExtension: JsonPathFunctionExtension<*>)
    fun getExtension(name: String): JsonPathFunctionExtension<*>?
    fun export(): Map<String, JsonPathFunctionExtension<*>>
}