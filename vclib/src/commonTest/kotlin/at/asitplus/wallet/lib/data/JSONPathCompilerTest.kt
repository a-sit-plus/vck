package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.data.jsonPath.jsonPathCompiler
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

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
                    .shouldNotBeNull().jsonArray.let { it[it.size - 1] }
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[0,1]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 2
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray.filterIndexed { index, jsonElement ->
                        index < 2
                    }.forEach {
                        it.shouldBeIn(nodeList)
                    }
            }

            "\$..book[:2]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 2
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray.filterIndexed { index, jsonElement ->
                        index < 2
                    }.forEach {
                        it.shouldBeIn(nodeList)
                    }
            }

            "\$..book[?@.isbn]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 2
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray.filter {
                        it.jsonObject.containsKey("isbn")
                    }.forEach {
                        it.shouldBeIn(nodeList)
                    }
            }

            "\$..book[?@.price<10]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 2
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray.filter {
                        it.jsonObject.get("price").shouldNotBeNull().jsonPrimitive.double < 10
                    }.forEach {
                        it.shouldBeIn(nodeList)
                    }
            }

            "\$..*" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(bookStore).map { it.value }
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().shouldBeIn(nodeList).jsonObject.let { store ->
                        store["book"].shouldNotBeNull().shouldBeIn(nodeList).jsonArray.forEach { book ->
                            book.shouldBeIn(nodeList).jsonObject.forEach { entry ->
                                entry.value.shouldBeIn(nodeList)
                            }
                        }
                        store["bicycle"].shouldNotBeNull().shouldBeIn(nodeList).jsonObject.forEach { entry ->
                            entry.value.shouldBeIn(nodeList)
                        }
                    }
            }
        }

        "2.1.3. Example" - {
            val jsonElement = jsonSerializer.decodeFromString<JsonElement>("{\"a\":[{\"b\":0},{\"b\":1},{\"c\":2}]}")
            "\$" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.shouldBeIn(nodeList)
            }
            "\$.a" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonObject["a"].shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.a[*]" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(jsonElement).map { it.value }
                nodeList shouldHaveSize 3
                jsonElement.jsonObject["a"].shouldNotBeNull().jsonArray.forEach {
                    it.shouldBeIn(nodeList)
                }
            }
            "\$.a[*].b" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonObject["a"].shouldNotBeNull().jsonArray.forEach {
                    it.shouldBeInstanceOf<JsonObject>()["b"]?.jsonPrimitive?.shouldBeIn(nodeList)
                }
            }
        }
        "2.2.3.  Examples" - {
            val jsonElement = jsonSerializer.decodeFromString<JsonElement>("{\"k\": \"v\"}")
            "$" {
                val nodeList = jsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                    .invoke(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.shouldBeIn(nodeList)
            }
        }
    }
})