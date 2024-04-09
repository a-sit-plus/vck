package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.agent.toJsonElement
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeExactly
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldHaveSameHashCodeAs
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject

class JSONPathParserTest : FreeSpec({
    "Root selector is retrieved without exceptions" {
        val selectors = JSONPathParser("$").getSelectors()
        selectors.size shouldBeExactly 1
        selectors.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
    }
    "Dot selector behaves the same as index selector for member names" {
        val selectors1 = JSONPathParser("\$['mdoc'].doctype").getSelectors()
        val selectors2 = JSONPathParser("\$.mdoc.doctype").getSelectors()

        selectors1.size shouldBeExactly 3
        selectors2.size shouldBeExactly 3

        selectors1.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()
        selectors2.get(0).shouldBeInstanceOf<JsonPathSelector.RootSelector>()

        selectors1.get(1).shouldBeInstanceOf<JsonPathSelector.IndexSelector>()
        (selectors1.get(1) as JsonPathSelector.IndexSelector).memberName shouldBe "mdoc"
        selectors2.get(1).shouldBeInstanceOf<JsonPathSelector.DotSelector>()
        (selectors2.get(1) as JsonPathSelector.DotSelector).objectMemberName shouldBe "mdoc"

        selectors1.get(2).shouldBeInstanceOf<JsonPathSelector.DotSelector>()
        selectors2.get(2).shouldBeInstanceOf<JsonPathSelector.DotSelector>()
    }
    "test parser wildcard selector" - {
        "test parser detects dot wildcard selector" {
            val selectors = JSONPathParser("$.*").getSelectors()
            selectors shouldHaveSize 2
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JsonPathSelector.DotWildCardSelector>()
        }
        "test parser detects index wildcard selector" {
            val selectors = JSONPathParser("$[*]").getSelectors()
            selectors shouldHaveSize 2
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JsonPathSelector.IndexWildCardSelector>()
        }
        "test parser detects index wildcard selector as first selector" {
            val selectors = JSONPathParser("$[*].vc").getSelectors()
            selectors shouldHaveSize 3
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JsonPathSelector.IndexWildCardSelector>()
            selectors[2].shouldBeInstanceOf<JsonPathSelector.DotSelector>()
        }
        "test parser detects index wildcard selector as second selector" {
            val selectors = JSONPathParser("$.vc[*]").getSelectors()
            selectors shouldHaveSize 3
            selectors[0].shouldBeInstanceOf<JsonPathSelector.RootSelector>()
            selectors[1].shouldBeInstanceOf<JsonPathSelector.DotSelector>()
            selectors[2].shouldBeInstanceOf<JsonPathSelector.IndexWildCardSelector>()
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

            (jsonObject.matchJsonPath("$.type").entries.first().value as JsonPrimitive).content shouldBe type
            jsonObject.matchJsonPath("$.vc").let { vcMatches ->
                vcMatches shouldHaveSize 1
                val vcArray = vcMatches.entries.first().value
                vcArray.shouldBeInstanceOf<JsonArray>()
                val vcArrayElements = JsonPathSelector.WildCardSelector().invoke(vcArray)
                vcArrayElements shouldHaveSize 3
            }

            val vcArrayElements = jsonObject.matchJsonPath("$.vc[*]")
            vcArrayElements shouldHaveSize 3
        }
    }
})
