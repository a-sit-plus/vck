package at.asitplus.wallet.lib.data.jsonPath

interface JSONPathFunctionExtensionManager {
    fun getExtension(name: String): JSONPathFunctionExtension<*>?
}