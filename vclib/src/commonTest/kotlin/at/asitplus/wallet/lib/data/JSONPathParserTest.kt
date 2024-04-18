package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.jsonPath.JSONPathSelector
import at.asitplus.wallet.lib.data.jsonPath.SimpleJSONPathQuery
import at.asitplus.wallet.lib.data.jsonPath.jsonPathCompiler
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

class JSONPathParserTest : FreeSpec({
    "Root selector is retrieved without exceptions" {
        val matcher = jsonPathCompiler.compile("$") as SimpleJSONPathQuery
        val selectors = matcher.selectors
        selectors.shouldNotBeNull()
        selectors.size shouldBeExactly 1
        selectors.get(0).shouldBeInstanceOf<JSONPathSelector.RootSelector>()
    }
    "Dot selector behaves the same as index selector for member names" {
        val matcher1 = jsonPathCompiler.compile("\$['mdoc'].doctype") as SimpleJSONPathQuery
        val selectors1 = matcher1.selectors

        val matcher2 = jsonPathCompiler.compile("\$.mdoc.doctype") as SimpleJSONPathQuery
        val selectors2 = matcher2.selectors

        selectors1.shouldNotBeNull()
        selectors2.shouldNotBeNull()

        selectors1.size shouldBeExactly 3
        selectors2.size shouldBeExactly 3

        selectors1.get(0).shouldBeInstanceOf<JSONPathSelector.RootSelector>()
        selectors2.get(0).shouldBeInstanceOf<JSONPathSelector.RootSelector>()

        selectors1.get(1).let {
            it.shouldBeInstanceOf<JSONPathSelector.UnionSelector>()
            it.selectors[0].shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
        }
        selectors2.get(1).shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
        (selectors2.get(1) as JSONPathSelector.MemberSelector).memberName shouldBe "mdoc"

        selectors1.get(2).shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
        selectors2.get(2).shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
    }
    "test parser wildcard selector" - {
        "test parser detects dot wildcard selector" {
            val matcher = jsonPathCompiler.compile("$.*") as SimpleJSONPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 2
            selectors[0].shouldBeInstanceOf<JSONPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JSONPathSelector.WildCardSelector>()
        }
        "test parser detects index wildcard selector" {
            val matcher = jsonPathCompiler.compile("\$[*]") as SimpleJSONPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 2
            selectors[0].shouldBeInstanceOf<JSONPathSelector.RootSelector>()
            val selector = selectors[1]
            selector.shouldBeInstanceOf<JSONPathSelector.UnionSelector>()
            selector.selectors[0].shouldBeInstanceOf<JSONPathSelector.WildCardSelector>()
        }
        "test parser detects index wildcard selector as first selector" {
            val matcher = jsonPathCompiler.compile("\$[*].vc") as SimpleJSONPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 3
            selectors[0].shouldBeInstanceOf<JSONPathSelector.RootSelector>()
            val selector = selectors[1]
            selector.shouldBeInstanceOf<JSONPathSelector.UnionSelector>()
            selector.selectors[0].shouldBeInstanceOf<JSONPathSelector.WildCardSelector>()
            selectors[2].shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
        }
        "test parser detects index wildcard selector as second selector" {
            val matcher = jsonPathCompiler.compile("\$.vc[*]") as SimpleJSONPathQuery
            val selectors = matcher.selectors
            selectors.shouldNotBeNull()
            selectors shouldHaveSize 3
            selectors[0].shouldBeInstanceOf<JSONPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
            val selector = selectors[2]
            selector.shouldBeInstanceOf<JSONPathSelector.UnionSelector>()
            selector.selectors[0].shouldBeInstanceOf<JSONPathSelector.WildCardSelector>()
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

            (jsonPathCompiler.compile("$.type").invoke(jsonObject).first().value as JsonPrimitive).content shouldBe type
            jsonPathCompiler.compile("$.vc").invoke(jsonObject).let { vcMatches ->
                vcMatches shouldHaveSize 1
                val vcArray = vcMatches.first().value
                vcArray.shouldBeInstanceOf<JsonArray>()
                val vcArrayElements = JSONPathSelector.WildCardSelector.invoke(vcArray)
                vcArrayElements shouldHaveSize 3
            }

            val vcArrayElements = jsonPathCompiler.compile("$.vc[*]").invoke(jsonObject)
            vcArrayElements shouldHaveSize 3
        }
    }
})
