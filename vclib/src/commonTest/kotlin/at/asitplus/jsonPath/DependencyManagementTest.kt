package at.asitplus.jsonpath

import at.asitplus.jsonpath.core.JsonPathCompiler
import at.asitplus.jsonpath.core.JsonPathFilterExpressionValue
import at.asitplus.jsonpath.core.JsonPathFunctionExtension
import at.asitplus.jsonpath.core.JsonPathQuery
import at.asitplus.jsonpath.core.JsonPathSelectorQuery
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.buildJsonObject

@Suppress("unused")
class DependencyManagementTest : FreeSpec({
    // making sure that the dependencies are reset to their default for the next test
    val defaultCompilerBuilderBackup = JsonPathDependencyManager.compiler
    var defaultTestFunctionExtensionRepository =
        JsonPathDependencyManager.functionExtensionRepository
    val defaultFunctionExtensionRepositoryBackup =
        JsonPathDependencyManager.functionExtensionRepository
    beforeEach {
        // prepare a dummy repository to be modified by the tests
        JsonPathDependencyManager.functionExtensionRepository =
            JsonPathFunctionExtensionMapRepository(
                JsonPathDependencyManager.functionExtensionRepository.export().toMutableMap()
            )
        defaultTestFunctionExtensionRepository =
            JsonPathDependencyManager.functionExtensionRepository
    }
    afterEach {
        JsonPathDependencyManager.apply {
            compiler = defaultCompilerBuilderBackup
            functionExtensionRepository = defaultFunctionExtensionRepositoryBackup
        }
    }

    "dependency manager compiler should support the functions in the repo at the time of compilation, and query should be executable afterwards too" - {
        "compiler that was built when the repository supported a function extension before it was removed should succeed compilation before and query afterwards" {
            val jsonPathStatement = "$[?foo()]"

            JsonPathDependencyManager.functionExtensionRepository.apply {
                addExtension(
                    object : JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                        name = "foo",
                        argumentTypes = listOf(),
                    ) {
                        override fun invoke(arguments: List<JsonPathFilterExpressionValue>): JsonPathFilterExpressionValue.LogicalTypeValue {
                            return JsonPathFilterExpressionValue.LogicalTypeValue(true)
                        }
                    }
                )
            }
            val jsonPath = shouldNotThrowAny {
                JsonPath(jsonPathStatement)
            }

            // this basically removes the foo-extension by changing to the default extension repository
            JsonPathDependencyManager.functionExtensionRepository =
                defaultTestFunctionExtensionRepository

            shouldNotThrowAny {
                val jsonElement = buildJsonObject {
                    put("a", JsonNull)
                }
                val nodeList = jsonPath.query(jsonElement)

                nodeList shouldHaveSize 1
                jsonElement["a"].shouldNotBeNull().shouldBeIn(nodeList.map { it.value })
            }
        }
    }

    "changing the compiler also changes the compiler used in the next JsonPath" {
        val incorrectEmptyQueryCompiler = object : JsonPathCompiler {
            override fun compile(jsonPath: String): JsonPathQuery {
                return JsonPathSelectorQuery(listOf())
            }
        }
        JsonPathDependencyManager.compiler = incorrectEmptyQueryCompiler
        val emptyQueryResult = JsonPath("$").query(buildJsonObject {})
        emptyQueryResult.shouldHaveSize(0) // the compiler always yields an empty query
    }
})
