package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

class JsonPath(
    jsonPath: String,
    compiler: JsonPathCompiler = defaultJsonPathCompiler,
) {
    private val query = compiler.compile(jsonPath)

    fun query(jsonElement: JsonElement): NodeList {
        return query.invoke(jsonElement)
    }
}