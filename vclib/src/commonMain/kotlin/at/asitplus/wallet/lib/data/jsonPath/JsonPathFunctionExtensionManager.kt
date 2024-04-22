package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.CountFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.LengthFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.MatchFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.SearchFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.ValueFunctionExtension

interface JsonPathFunctionExtensionManager {
    fun addExtension(functionExtension: JsonPathFunctionExtension<*>)
    fun removeExtension(functionExtensionName: String)
    fun getExtension(name: String): JsonPathFunctionExtension<*>?
}

val defaultFunctionExtensionManager: JsonPathFunctionExtensionManager by lazy {
    object : JsonPathFunctionExtensionManager {
        private val extensions: MutableMap<String, JsonPathFunctionExtension<*>> = mutableMapOf()

        override fun addExtension(functionExtension: JsonPathFunctionExtension<*>) {
            if(extensions.containsKey(functionExtension.name)) {
                throw FunctionExtensionCollisionException(functionExtension.name)
            }
            extensions.put(functionExtension.name, functionExtension)
        }

        override fun removeExtension(functionExtensionName: String) {
            extensions.remove(functionExtensionName)
        }

        override fun getExtension(name: String): JsonPathFunctionExtension<*>? {
            return extensions.get(name)
        }
    }.apply {
        addExtension(LengthFunctionExtension)
        addExtension(CountFunctionExtension)
        addExtension(MatchFunctionExtension)
        addExtension(SearchFunctionExtension)
        addExtension(ValueFunctionExtension)
    }
}

class FunctionExtensionCollisionException(val functionName: String) : Exception(
    "A function extension with the name \"$functionName\" has already been registered."
)