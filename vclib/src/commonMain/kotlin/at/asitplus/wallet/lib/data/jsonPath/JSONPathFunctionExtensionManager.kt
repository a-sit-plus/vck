package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.CountFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.LengthFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.MatchFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.SearchFunctionExtension
import at.asitplus.wallet.lib.data.jsonPath.functionExtensions.ValueFunctionExtension

interface JSONPathFunctionExtensionManager {
    fun addExtension(functionExtension: JSONPathFunctionExtension<*>)
    fun getExtension(name: String): JSONPathFunctionExtension<*>?
}

val defaultFunctionExtensionManager by lazy {
    object : JSONPathFunctionExtensionManager {
        private val extensions: MutableMap<String, JSONPathFunctionExtension<*>> = mutableMapOf()

        override fun addExtension(functionExtension: JSONPathFunctionExtension<*>) {
            if(extensions.containsKey(functionExtension.name)) {
                throw FunctionExtensionCollisionException(functionExtension.name)
            }
            extensions.put(functionExtension.name, functionExtension)
        }

        override fun getExtension(name: String): JSONPathFunctionExtension<*>? {
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