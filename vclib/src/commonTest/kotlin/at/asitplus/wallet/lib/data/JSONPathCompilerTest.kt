package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.jsonPath.JSONPathSelector
import at.asitplus.wallet.lib.data.jsonPath.SimpleJSONPathMatcher
import at.asitplus.wallet.lib.data.jsonPath.jsonPathCompiler
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonElement

class JSONPathCompilerTest : FreeSpec({
    "tests from https://datatracker.ietf.org/doc/rfc9535/" - {
        "1.5.  JSONPath Examples" - {
            val bookStore = jsonSerializer.decodeFromString<JsonElement>(
                "   { \"store\": {\n" +
                        "       \"book\": [\n" +
                        "         { \"category\": \"reference\",\n" +
                        "           \"author\": \"Nigel Rees\",\n" +
                        "           \"title\": \"Sayings of the Century\",\n" +
                        "           \"price\": 8.95\n" +
                        "         },\n" +
                        "         { \"category\": \"fiction\",\n" +
                        "           \"author\": \"Evelyn Waugh\",\n" +
                        "           \"title\": \"Sword of Honour\",\n" +
                        "           \"price\": 12.99\n" +
                        "         },\n" +
                        "         { \"category\": \"fiction\",\n" +
                        "           \"author\": \"Herman Melville\",\n" +
                        "           \"title\": \"Moby Dick\",\n" +
                        "           \"isbn\": \"0-553-21311-3\",\n" +
                        "           \"price\": 8.99\n" +
                        "         },\n" +
                        "         { \"category\": \"fiction\",\n" +
                        "           \"author\": \"J. R. R. Tolkien\",\n" +
                        "           \"title\": \"The Lord of the Rings\",\n" +
                        "           \"isbn\": \"0-395-19395-8\",\n" +
                        "           \"price\": 22.99\n" +
                        "         }\n" +
                        "       ],\n" +
                        "       \"bicycle\": {\n" +
                        "         \"color\": \"red\",\n" +
                        "         \"price\": 399\n" +
                        "       }\n" +
                        "     }\n" +
                        "   }"
            )

            "$.store.book[*].author" {
                val matcher = jsonPathCompiler.compile(this.testScope.testCase.name.originalName) as SimpleJSONPathMatcher
                val selectors = matcher.selectors
                selectors.shouldNotBeNull()
                selectors shouldHaveSize 5
                selectors[0].shouldBeInstanceOf<JSONPathSelector.RootSelector>()
                selectors[0].shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
                selectors[0].shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
                selectors[0].shouldBeInstanceOf<JSONPathSelector.WildCardSelector>()
                selectors[0].shouldBeInstanceOf<JSONPathSelector.MemberSelector>()
            }
        }
    }
})