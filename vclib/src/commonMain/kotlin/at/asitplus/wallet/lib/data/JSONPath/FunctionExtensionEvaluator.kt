package at.asitplus.wallet.lib.data.JSONPath

interface FunctionExtensionEvaluator {
    fun invoke(arguments: List<JSONPathFilterValue>): JSONPathFilterValue
}