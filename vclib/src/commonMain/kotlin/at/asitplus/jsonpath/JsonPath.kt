package at.asitplus.jsonpath

import at.asitplus.jsonpath.core.JsonPathCompiler
import at.asitplus.jsonpath.core.NodeList
import kotlinx.serialization.json.JsonElement

class JsonPath(
    jsonPath: String,
    compiler: JsonPathCompiler = JsonPathDependencyManager.compiler,
) {
    private val query = compiler.compile(jsonPath)

    fun query(jsonElement: JsonElement): NodeList {
        return query.invoke(jsonElement)
    }
}