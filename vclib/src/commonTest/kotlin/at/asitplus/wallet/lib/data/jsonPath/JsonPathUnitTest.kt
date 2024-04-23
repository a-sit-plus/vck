package at.asitplus.wallet.lib.data.jsonPath

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Suppress("unused")
class JsonPathUnitTest : FreeSpec({
    "Examples from https://datatracker.ietf.org/doc/rfc9535/" - {
        "1.5.  JSONPath Examples" - {
            val bookStore = Json.decodeFromString<JsonElement>(
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 2
                val store =
                    bookStore.jsonObject["store"].shouldNotBeNull().jsonObject
                store.get("book").shouldNotBeNull().shouldBeIn(nodeList)
                store.get("bicycle").shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$.store..price" {
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 5
                val store =
                    bookStore.jsonObject["store"].shouldNotBeNull().jsonObject
                store.get("book").shouldNotBeNull().jsonArray.forEach {
                    it.jsonObject["price"].shouldBeIn(nodeList)
                }
                store.get("bicycle").shouldNotBeNull().jsonObject["price"].shouldNotBeNull()
                    .shouldBeIn(nodeList)
            }

            "\$..book[2]" {
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray[2]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[2].author" {
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray[2]
                    .shouldNotBeNull().jsonObject["author"]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[2].publisher" {
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 0
            }

            "\$..book[-1]" {
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                nodeList shouldHaveSize 1
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().jsonObject["book"]
                    .shouldNotBeNull().jsonArray.let { it[it.size - 1] }
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }

            "\$..book[0,1]" {
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
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
                val nodeList =
                    defaultJsonPathCompiler.compile(this.testScope.testCase.name.originalName)
                        .invoke(bookStore).map { it.value }
                bookStore.jsonObject["store"]
                    .shouldNotBeNull().shouldBeIn(nodeList).jsonObject.let { store ->
                        store["book"].shouldNotBeNull()
                            .shouldBeIn(nodeList).jsonArray.forEach { book ->
                                book.shouldBeIn(nodeList).jsonObject.forEach { entry ->
                                    entry.value.shouldBeIn(nodeList)
                                }
                            }
                        store["bicycle"].shouldNotBeNull()
                            .shouldBeIn(nodeList).jsonObject.forEach { entry ->
                                entry.value.shouldBeIn(nodeList)
                            }
                    }
            }
        }

        "2.1. Overview" - {
            val jsonElement =
                Json.decodeFromString<JsonElement>("{\"a\":[{\"b\":0},{\"b\":1},{\"c\":2}]}")
            "\$" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.shouldBeIn(nodeList)
            }
            "\$.a" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonObject["a"].shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.a[*]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 3
                jsonElement.jsonObject["a"].shouldNotBeNull().jsonArray.forEach {
                    it.shouldBeIn(nodeList)
                }
            }
            "\$.a[*].b" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonObject["a"].shouldNotBeNull().jsonArray.forEach {
                    it.shouldBeInstanceOf<JsonObject>()["b"]?.jsonPrimitive?.shouldBeIn(nodeList)
                }
            }
        }

        "2.2. Root Identifier" - {
            val jsonElement = Json.decodeFromString<JsonElement>("{\"k\": \"v\"}")
            "$" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.shouldBeIn(nodeList)
            }
        }

        "2.3.1. Name Selector" - {
            val jsonElement = Json.decodeFromString<JsonElement>(
                "{\n" +
                        "                \"o\": {\"j j\": {\"k.k\": 3}},\n" +
                        "                \"'\": {\"@\": 2}\n" +
                        "            }"
            )
            "\$.o['j j']" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonObject.get("o")
                    .shouldNotBeNull().jsonObject["j j"]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.o['j j']['k.k']" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonObject.get("o")
                    .shouldNotBeNull().jsonObject["j j"]
                    .shouldNotBeNull().jsonObject["k.k"]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.o[\"j j\"][\"k.k\"]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonObject.get("o")
                    .shouldNotBeNull().jsonObject["j j"]
                    .shouldNotBeNull().jsonObject["k.k"]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$[\"'\"][\"@\"]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonObject.get("'")
                    .shouldNotBeNull().jsonObject["@"]
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }
        }

        "2.3.2. Wildcard Selector" - {
            val jsonElement = Json.decodeFromString<JsonElement>(
                "   {\n" +
                        "     \"o\": {\"j\": 1, \"k\": 2},\n" +
                        "     \"a\": [5, 3]\n" +
                        "   }"
            )
            "\$[*]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonObject.get("o")
                    .shouldNotBeNull().shouldBeIn(nodeList)
                jsonElement.jsonObject.get("a")
                    .shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.o[*]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonObject["o"].shouldNotBeNull().let {
                    it.jsonObject["j"]
                        .shouldNotBeNull().shouldBeIn(nodeList)
                    it.jsonObject["k"]
                        .shouldNotBeNull().shouldBeIn(nodeList)
                }
            }
            "\$.o[*, *]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 4
                jsonElement.jsonObject["o"].shouldNotBeNull().let {
                    it.jsonObject["j"]
                        .shouldNotBeNull().shouldBeIn(nodeList).let { j ->
                            nodeList.count {
                                it == j
                            }.shouldBe(2)
                        }
                    it.jsonObject["k"]
                        .shouldNotBeNull().shouldBeIn(nodeList).let { k ->
                            nodeList.count {
                                it == k
                            }.shouldBe(2)
                        }
                }
            }
            "\$.a[*]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonObject["a"].shouldNotBeNull().let {
                    it.jsonArray[0]
                        .shouldNotBeNull().shouldBeIn(nodeList).let { zero ->
                            nodeList.count {
                                it == zero
                            }.shouldBe(1)
                        }
                    it.jsonArray[1]
                        .shouldNotBeNull().shouldBeIn(nodeList).let { one ->
                            nodeList.count {
                                it == one
                            }.shouldBe(1)
                        }
                }
            }
        }

        "2.3.3.  Index Selector" - {
            val jsonElement = Json.decodeFromString<JsonElement>("[\"a\",\"b\"]")

            "\$[1]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonArray[1].shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$[-2]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 1
                jsonElement.jsonArray[0].shouldNotBeNull().shouldBeIn(nodeList)
            }
        }

        "2.3.4.  Array Slice Selector" - {
            val jsonElement =
                Json.decodeFromString<JsonElement>("[\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\"]")

            "\$[1:3]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonArray[1].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[0].shouldBe(it)
                }
                jsonElement.jsonArray[2].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[1].shouldBe(it)
                }
            }
            "\$[5:]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonArray[5].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[0].shouldBe(it)
                }
                jsonElement.jsonArray[6].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[1].shouldBe(it)
                }
            }
            "\$[1:5:2]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonArray[1].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[0].shouldBe(it)
                }
                jsonElement.jsonArray[3].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[1].shouldBe(it)
                }
            }
            "\$[5:1:-2]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 2
                jsonElement.jsonArray[5].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[0].shouldBe(it)
                }
                jsonElement.jsonArray[3].shouldNotBeNull().shouldBeIn(nodeList).let {
                    nodeList[1].shouldBe(it)
                }
            }
            "\$[::-1]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }
                nodeList shouldHaveSize 7
                for (i in 6.downTo(0)) {
                    jsonElement.jsonArray[i].shouldNotBeNull().shouldBeIn(nodeList).let {
                        nodeList[6 - i].shouldBe(it)
                    }
                }
            }
        }

        "2.3.5.  Filter Selector" - {
            "Comparisons" - {
                // since this should be compiler agnostic, check whether the evaluation is correct by using
                // the return list as an indicator for true/false:
                // - if the result should be true, all children should be returned, otherwise zero
                val jsonElement = Json.decodeFromString<JsonElement>(
                    "{\n" +
                            "     \"obj\": {\"x\": \"y\"},\n" +
                            "     \"arr\": [2, 3]\n" +
                            "   }"
                ).jsonObject

                "\$[?\$.absent1 == \$.absent2]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.absent1 <= \$.absent2 ]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.absent == 'g']" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.absent1 != \$.absent2]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.absent != 'g']" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?1 <= 2]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?1 > 2]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?13 == '13']" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?'a' <= 'b']" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?'a' > 'b']" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.obj == \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.obj != \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.obj == \$.obj]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.obj != \$.obj]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.arr == \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.arr != \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.obj == 17]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.obj != 17]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.obj <= \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.obj < \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?\$.obj <= \$.obj]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?\$.arr <= \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?1 <= \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?1 >= \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?1 > \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?1 < \$.arr]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
                "\$[?true <= true]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize jsonElement.size
                }
                "\$[?true > true]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }
                    nodeList shouldHaveSize 0
                }
            }
            "Queries" - {
                val jsonElement = Json.decodeFromString<JsonElement>(
                    "{\n" +
                            "     \"a\": [3, 5, 1, 2, 4, 6,\n" +
                            "           {\"b\": \"j\"},\n" +
                            "           {\"b\": \"k\"},\n" +
                            "           {\"b\": {}},\n" +
                            "           {\"b\": \"kilo\"}\n" +
                            "          ],\n" +
                            "     \"o\": {\"p\": 1, \"q\": 2, \"r\": 3, \"s\": 5, \"t\": {\"u\": 6}},\n" +
                            "     \"e\": \"f\"\n" +
                            "   }"
                ).jsonObject


                "\$.a[?@.b == 'kilo']" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 1
                    jsonElement.jsonObject["a"].shouldNotBeNull()
                        .jsonArray.get(9).shouldNotBeNull().shouldBeIn(nodeList)
                }
                "\$.a[?(@.b == 'kilo')]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 1
                    jsonElement.jsonObject["a"].shouldNotBeNull()
                        .jsonArray.get(9).shouldNotBeNull().shouldBeIn(nodeList)
                }
                "\$.a[?@>3.5)]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 3
                    jsonElement.jsonObject["a"].shouldNotBeNull().let { a ->
                        a.jsonArray.get(1).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(4).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(5).shouldNotBeNull().shouldBeIn(nodeList)
                    }
                }
                "\$.a[?@.b)]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 4
                    jsonElement.jsonObject["a"].shouldNotBeNull().let { a ->
                        a.jsonArray.get(6).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(7).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(8).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(9).shouldNotBeNull().shouldBeIn(nodeList)
                    }
                }
                "\$[?@.*]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 2
                    jsonElement.jsonObject["a"].shouldNotBeNull().shouldBeIn(nodeList)
                    jsonElement.jsonObject["o"].shouldNotBeNull().shouldBeIn(nodeList)
                }
                "\$[?@[?@.b]]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 1
                    jsonElement.jsonObject["a"].shouldNotBeNull().shouldBeIn(nodeList)
                }
                "\$.o[?@<3, ?@<3]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 4
                    jsonElement.jsonObject["o"].shouldNotBeNull().jsonObject.let { o ->
                        o["p"].shouldNotBeNull().shouldBeIn(nodeList).let { p ->
                            nodeList.count {
                                it == p
                            }.shouldBe(2)
                        }
                        o["q"].shouldNotBeNull().shouldBeIn(nodeList).let { q ->
                            nodeList.count {
                                it == q
                            }.shouldBe(2)
                        }
                    }
                }
                "\$.a[?@<2 || @.b == \"k\"]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 2
                    jsonElement.jsonObject["a"].shouldNotBeNull().let { a ->
                        a.jsonArray.get(2).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(7).shouldNotBeNull().shouldBeIn(nodeList)
                    }
                }
                "\$.a[?match(@.b, \"[jk]\")]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 2
                    jsonElement.jsonObject["a"].shouldNotBeNull().let { a ->
                        a.jsonArray.get(6).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(7).shouldNotBeNull().shouldBeIn(nodeList)
                    }
                }
                "\$.a[?search(@.b, \"[jk]\")]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 3
                    jsonElement.jsonObject["a"].shouldNotBeNull().let { a ->
                        a.jsonArray.get(6).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(7).shouldNotBeNull().shouldBeIn(nodeList)
                        a.jsonArray.get(9).shouldNotBeNull().shouldBeIn(nodeList)
                    }
                }
                "\$.o[?@>1 && @<4]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 2
                    jsonElement.jsonObject["o"].shouldNotBeNull().jsonObject.let { o ->
                        o["q"].shouldNotBeNull().shouldBeIn(nodeList)
                        o["r"].shouldNotBeNull().shouldBeIn(nodeList)
                    }
                }
                "\$.o[?@.u || @.x]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 1
                    jsonElement.jsonObject["o"].shouldNotBeNull().jsonObject
                        .get("t").shouldNotBeNull().shouldBeIn(nodeList)
                }
                "\$.a[?@.b == $.x]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 6
                    jsonElement.jsonObject["a"].shouldNotBeNull().jsonArray.let { a ->
                        nodeList[0].shouldBe(a[0])
                        nodeList[1].shouldBe(a[1])
                        nodeList[2].shouldBe(a[2])
                        nodeList[3].shouldBe(a[3])
                        nodeList[4].shouldBe(a[4])
                        nodeList[5].shouldBe(a[5])
                    }
                }
                "\$.a[?@ || @]" {
                    val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                        .query(jsonElement).map { it.value }

                    nodeList shouldHaveSize 10
                    jsonElement.jsonObject["a"].shouldNotBeNull().jsonArray.let { a ->
                        for(index in 0..9) {
                            nodeList[index].shouldBe(a[index])
                        }
                    }
                }
            }
        }

        "2.4. Function Extensions" - {
            "\$[?length(@) < 3]" {
                shouldNotThrowAny {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?length(@.*) < 3]" {
                shouldThrow<JsonPathTypeCheckerException> {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?count(@.*) == 1]" {
                shouldNotThrowAny {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?count(1) == 1]" {
                shouldThrow<JsonPathTypeCheckerException> {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?count(foo(@.*)) == 1]" {
                defaultJsonPathFunctionExtensionManager.addExtension(
                    object: JsonPathFunctionExtension.NodesTypeFunctionExtension(
                        name = "foo",
                        argumentTypes = listOf(JsonPathExpressionType.NodesType),
                    ) {
                        override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.NodesTypeValue.FunctionExtensionResult {
                            TODO("Not yet implemented")
                        }
                    }
                )
                shouldNotThrowAny {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?match(@.timezone, 'Europe/.*') == true]" {
                shouldThrow<JsonPathTypeCheckerException> {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?value(@..color) == 'red']" {
                shouldNotThrowAny {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?value(@..color)]" {
                shouldThrow<JsonPathTypeCheckerException> {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?bar(@.a)]" - {
                "logical type argument" {
                    defaultJsonPathFunctionExtensionManager.putExtension(
                        object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                            name = "bar",
                            argumentTypes = listOf(JsonPathExpressionType.LogicalType),
                        ) {
                            override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                                TODO("Not yet implemented")
                            }
                        }
                    )
                    shouldNotThrowAny {
                        JsonPath(this.testScope.testCase.parent!!.name.originalName)
                    }
                }
                "value type argument" {
                    defaultJsonPathFunctionExtensionManager.putExtension(
                        object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                            name = "bar",
                            argumentTypes = listOf(JsonPathExpressionType.ValueType),
                        ) {
                            override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                                TODO("Not yet implemented")
                            }
                        }
                    )
                    shouldNotThrowAny {
                        JsonPath(this.testScope.testCase.parent!!.name.originalName)
                    }
                }
                "nodes type argument" {
                    defaultJsonPathFunctionExtensionManager.putExtension(
                        object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                            name = "bar",
                            argumentTypes = listOf(JsonPathExpressionType.NodesType),
                        ) {
                            override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                                TODO("Not yet implemented")
                            }
                        }
                    )
                    shouldNotThrowAny {
                        JsonPath(this.testScope.testCase.parent!!.name.originalName)
                    }
                }
            }
            "\$[?bnl(@.*)]" - {
                "logical type argument" {
                    defaultJsonPathFunctionExtensionManager.putExtension(
                        object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                            name = "bnl",
                            argumentTypes = listOf(JsonPathExpressionType.LogicalType),
                        ) {
                            override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                                TODO("Not yet implemented")
                            }
                        }
                    )
                    shouldNotThrowAny {
                        JsonPath(this.testScope.testCase.parent!!.name.originalName)
                    }
                }
                "value type argument" {
                    defaultJsonPathFunctionExtensionManager.putExtension(
                        object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                            name = "bnl",
                            argumentTypes = listOf(JsonPathExpressionType.ValueType),
                        ) {
                            override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                                TODO("Not yet implemented")
                            }
                        }
                    )
                    shouldThrow<JsonPathTypeCheckerException> {
                        JsonPath(this.testScope.testCase.parent!!.name.originalName)
                    }
                }
                "nodes type argument" {
                    defaultJsonPathFunctionExtensionManager.putExtension(
                        object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                            name = "bnl",
                            argumentTypes = listOf(JsonPathExpressionType.NodesType),
                        ) {
                            override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                                TODO("Not yet implemented")
                            }
                        }
                    )
                    shouldNotThrowAny {
                        JsonPath(this.testScope.testCase.parent!!.name.originalName)
                    }
                }
            }
            "\$[?blt(1==1)]" {
                defaultJsonPathFunctionExtensionManager.putExtension(
                    object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                        name = "blt",
                        argumentTypes = listOf(JsonPathExpressionType.LogicalType),
                    ) {
                        override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                            TODO("Not yet implemented")
                        }
                    }
                )
                shouldNotThrowAny {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?blt(1)]" {
                defaultJsonPathFunctionExtensionManager.putExtension(
                    object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                        name = "blt",
                        argumentTypes = listOf(JsonPathExpressionType.LogicalType),
                    ) {
                        override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                            TODO("Not yet implemented")
                        }
                    }
                )
                shouldThrow<JsonPathTypeCheckerException> {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
            "\$[?bal(1)]" {
                defaultJsonPathFunctionExtensionManager.putExtension(
                    object: JsonPathFunctionExtension.LogicalTypeFunctionExtension(
                        name = "bal",
                        argumentTypes = listOf(JsonPathExpressionType.ValueType),
                    ) {
                        override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
                            TODO("Not yet implemented")
                        }
                    }
                )
                shouldNotThrowAny {
                    JsonPath(this.testScope.testCase.name.originalName)
                }
            }
        }

        "2.5.1.  Child Segment" - {
            val jsonElement = Json.decodeFromString<JsonElement>(
                "[\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\"]"
            ).jsonArray
            "\$[0, 3]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 2
                nodeList[0].shouldBe(jsonElement[0])
                nodeList[1].shouldBe(jsonElement[3])
            }
            "\$[0:2,5]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 3
                nodeList[0].shouldBe(jsonElement[0])
                nodeList[1].shouldBe(jsonElement[1])
                nodeList[2].shouldBe(jsonElement[5])
            }
            "\$[0,0]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 2
                nodeList[0].shouldBe(jsonElement[0])
                nodeList[1].shouldBe(jsonElement[0])
            }
        }

        "2.5.2.  Descendant Segment" - {
            val jsonElement = Json.decodeFromString<JsonElement>(
                "{\n" +
                        "     \"o\": {\"j\": 1, \"k\": 2},\n" +
                        "     \"a\": [5, 3, [{\"j\": 4}, {\"k\": 6}]]\n" +
                        "   }"
            ).jsonObject
            "\$..j" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 2
                jsonElement["o"].shouldNotBeNull().jsonObject["j"].shouldBeIn(nodeList)
                jsonElement["a"].shouldNotBeNull()
                    .jsonArray[2].shouldNotBeNull()
                    .jsonArray[0].shouldNotBeNull()
                    .jsonObject["j"].shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$..[0]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 2
                jsonElement["a"].shouldNotBeNull().jsonArray.let { a ->
                    a.jsonArray[0].shouldNotBeNull().shouldBe(nodeList[0])
                    a.jsonArray[2].shouldNotBeNull().jsonArray[0].shouldBe(nodeList[1])
                }
            }
            "\$..[*]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 11
                jsonElement["a"].shouldNotBeNull().shouldBeIn(nodeList).jsonArray.let { a ->
                    a.forEach { item ->
                        item.shouldBeIn(nodeList)
                    }
                    a[2].shouldNotBeNull().jsonArray.let { a2 ->
                        a2.forEach { a2children ->
                            a2children.shouldBeIn(nodeList)
                            a2children.jsonObject.forEach {
                                it.value.shouldBeIn(nodeList)
                            }
                        }
                    }
                }
                jsonElement["o"].shouldNotBeNull().shouldBeIn(nodeList).jsonObject.let { o ->
                    o.forEach { item ->
                        item.value.shouldBeIn(nodeList)
                    }
                }
            }
            "\$..*" { // same as the one before this
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 11
                jsonElement["a"].shouldNotBeNull().shouldBeIn(nodeList).jsonArray.let { a ->
                    a.forEach { item ->
                        item.shouldBeIn(nodeList)
                    }
                    a[2].shouldNotBeNull().jsonArray.let { a2 ->
                        a2.forEach { a2children ->
                            a2children.shouldBeIn(nodeList)
                            a2children.jsonObject.forEach {
                                it.value.shouldBeIn(nodeList)
                            }
                        }
                    }
                }
                jsonElement["o"].shouldNotBeNull().shouldBeIn(nodeList).jsonObject.let { o ->
                    o.forEach { item ->
                        item.value.shouldBeIn(nodeList)
                    }
                }
            }
            "\$..o" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["o"].shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.o..[*, *]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 4
                jsonElement["o"].shouldNotBeNull().jsonObject.let { o ->
                    o.forEach { oDescendant ->
                        oDescendant.value.shouldBeIn(nodeList)
                        nodeList.count {
                            it == oDescendant.value
                        } shouldBe 2
                    }
                }
            }
            "\$.a..[0, 1]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 4
                jsonElement["a"].shouldNotBeNull().jsonArray.let { a ->
                    listOf(a, a[2]).forEach { descendant ->
                        descendant.jsonArray[0].shouldBeIn(nodeList)
                        descendant.jsonArray[1].shouldBeIn(nodeList)
                    }
                }
            }
        }

        "2.6.  Semantics of null" - {
            val jsonElement = Json.decodeFromString<JsonElement>(
                "   {\"a\": null, \"b\": [null], \"c\": [{}], \"null\": 1}"
            ).jsonObject
            "\$.a" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["a"].shouldNotBeNull().shouldBeIn(nodeList)
            }
            "\$.a[0]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 0
            }
            "\$.a.d" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 0
            }
            "\$.b[0]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["b"].shouldNotBeNull().jsonArray[0].shouldBeIn(nodeList)
            }
            "\$.b[*]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["b"].shouldNotBeNull().jsonArray.mapIndexed { index, value ->
                    nodeList[index].shouldBe(value)
                }
            }
            "\$.b[?@]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["b"].shouldNotBeNull().jsonArray.mapIndexed { index, value ->
                    nodeList[index].shouldBe(value)
                }
            }
            "\$.b[?@==null]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["b"].shouldNotBeNull().jsonArray.mapIndexed { index, value ->
                    nodeList[index].shouldBe(value)
                }
            }
            "\$.c[?@.d==null]" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 0
            }
            "\$.null" {
                val nodeList = JsonPath(this.testScope.testCase.name.originalName)
                    .query(jsonElement).map { it.value }

                nodeList shouldHaveSize 1
                jsonElement["null"].shouldNotBeNull().shouldBeIn(nodeList)
            }
        }
    }
})
