package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.jsonPath.jsonPathCompiler
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

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
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 4
                val bookArray =
                    bookStore.jsonObject["store"].shouldNotBeNull().jsonObject["book"].shouldNotBeNull().jsonArray
                bookArray.forEach {
                    val author = it.jsonObject["author"].shouldNotBeNull()
                    author.shouldBeIn(nodeList)
                }
            }

            "$..author" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 4
                val bookArray =
                    bookStore.jsonObject["store"].shouldNotBeNull().jsonObject["book"].shouldNotBeNull().jsonArray
                bookArray.forEach {
                    val author = it.jsonObject["author"].shouldNotBeNull()
                    author.shouldBeIn(nodeList)
                }
            }

            "\$.store.*" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 2
                val store =
                    bookStore.jsonObject["store"].shouldNotBeNull().jsonObject
                store.get("book").shouldNotBeNull().shouldBeIn(nodeList)
                store.get("bicycle").shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$.store..price" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 5
                val store =
                    bookStore.jsonObject["store"].shouldNotBeNull().jsonObject
                store.get("book").shouldNotBeNull().jsonArray.forEach {
                    it.jsonObject["price"].shouldBeIn(nodeList)
                }
                store.get("bicycle").shouldNotBeNull().jsonObject["price"].shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[2]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray[2]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[2].author" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray[2]
                    .shouldNotBeNull().jsonObject["author"]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[2].publisher" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 0
            }

            "\$..book[-1]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray[-1]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[-1]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray[-1]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }
        }
    }
})