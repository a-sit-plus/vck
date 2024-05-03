package at.asitplus.jsonpath

import at.asitplus.jsonpath.core.JsonPathFunctionExtension

internal class JsonPathFunctionExtensionMapRepository(
    private val extensions: MutableMap<String, JsonPathFunctionExtension<*>> = mutableMapOf()
) : JsonPathFunctionExtensionRepository {
    override fun addExtension(functionExtension: JsonPathFunctionExtension<*>) {
        if(extensions.containsKey(functionExtension.name)) {
            throw FunctionExtensionCollisionException(functionExtension.name)
        }
        extensions[functionExtension.name] = functionExtension
    }
    override fun getExtension(name: String): JsonPathFunctionExtension<*>? {
        return extensions[name]
    }
    override fun export(): Map<String, JsonPathFunctionExtension<*>> {
        return extensions.toMap()
    }
}

class FunctionExtensionCollisionException(val functionName: String) : Exception(
    "A function extension with the name \"$functionName\" has already been registered."
)