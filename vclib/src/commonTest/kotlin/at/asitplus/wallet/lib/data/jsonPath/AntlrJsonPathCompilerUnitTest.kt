package at.asitplus.wallet.lib.data.jsonPath

import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject

class AntlrJsonPathCompilerUnitTest : FreeSpec({
    val compiler = AntlrJsonPathCompiler(
        functionExtensionRetriever = defaultFunctionExtensionManager::getExtension,
    )
    "Root selector is retrieved without exceptions" {
        val matcher = compiler.compile("$") as SimpleJsonPathQuery
        val selectors = matcher.selectors
        selectors.shouldNotBeNull()
        selectors.size shouldBeExactly 1
        selectors.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
    }
    "Dot selector behaves the same as index selector for member names" {
        val matcher1 = compiler.compile("\$['mdoc'].doctype") as SimpleJsonPathQuery
        val selectors1 = matcher1.selectors

        val matcher2 = compiler.compile("\$.mdoc.doctype") as SimpleJsonPathQuery
        val selectors2 = matcher2.selectors

        selectors1.shouldNotBeNull()
        selectors2.shouldNotBeNull()

        selectors1.size shouldBeExactly 3
        selectors2.size shouldBeExactly 3

        selectors1.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
        selectors2.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()

        selectors1.get(1).let {
            it.shouldBeInstanceOf<JsonPathSelector.UnionSelector>()
            it.selectors[0].shouldBeInstanceOf<JsonPathSelector.MemberSelector>()
        }
        selectors2.get(1).shouldBeInstanceOf<JsonPathSelector.MemberSelector>()
        (selectors2.get(1) as JsonPathSelector.MemberSelector).memberName shouldBe "mdoc"

        selectors1.get(2).shouldBeInstanceOf<JsonPathSelector.MemberSelector>()
        selectors2.get(2).shouldBeInstanceOf<JsonPathSelector.MemberSelector>()
    }
    "test parser wildcard selector" - {
        "test parser detects dot wildcard selector" {
            val matcher = compiler.compile("$.*") as SimpleJsonPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 2
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JsonPathSelector.WildCardSelector>()
        }
        "test parser detects index wildcard selector" {
            val matcher = compiler.compile("\$[*]") as SimpleJsonPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 2
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            val selector = selectors[1]
            selector.shouldBeInstanceOf<JsonPathSelector.UnionSelector>()
            selector.selectors[0].shouldBeInstanceOf<JsonPathSelector.WildCardSelector>()
        }
        "test parser detects index wildcard selector as first selector" {
            val matcher = compiler.compile("\$[*].vc") as SimpleJsonPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 3
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            val selector = selectors[1]
            selector.shouldBeInstanceOf<JsonPathSelector.UnionSelector>()
            selector.selectors[0].shouldBeInstanceOf<JsonPathSelector.WildCardSelector>()
            selectors[2].shouldBeInstanceOf<JsonPathSelector.MemberSelector>()
        }
        "test parser detects index wildcard selector as second selector" {
            val matcher = compiler.compile("\$.vc[*]") as SimpleJsonPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 3
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JsonPathSelector.MemberSelector>()
            val selector = selectors[2]
            selector.shouldBeInstanceOf<JsonPathSelector.UnionSelector>()
            selector.selectors[0].shouldBeInstanceOf<JsonPathSelector.WildCardSelector>()
        }
        "test wildcard selector from manually built json object" {
            val type = "AtomicAttribute2023"
            val jsonObject = buildJsonObject {
                put("type", JsonPrimitive(type))
                put("vc", buildJsonArray {
                    add(JsonPrimitive("1"))
                    add(JsonPrimitive("2"))
                    add(JsonPrimitive("3"))
                })
            }
            jsonObject.shouldNotBeNull()

            (compiler.compile("$.type").invoke(jsonObject).first().value as JsonPrimitive).content shouldBe type
            compiler.compile("$.vc").invoke(jsonObject).let { vcMatches ->
                vcMatches shouldHaveSize 1
                val vcArray = vcMatches.first().value
                vcArray.shouldBeInstanceOf<JsonArray>()
                val vcArrayElements = JsonPathSelector.WildCardSelector.invoke(vcArray)
                vcArrayElements shouldHaveSize 3
            }

            val vcArrayElements = compiler.compile("$.vc[*]").invoke(jsonObject)
            vcArrayElements shouldHaveSize 3
        }
    }
})
