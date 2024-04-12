package at.asitplus.wallet.lib.data.JSONPath

//// specification: https://datatracker.ietf.org/doc/rfc9535/
//open class JSONPathParserException(message: String) : Exception(message)
//
//class InvalidJsonPathException(val jsonPath: String) : JSONPathParserException(jsonPath)
//
//class JSONPathConstants {
//    companion object {
//        const val ROOT_INDICATOR = '$'
//    }
//}
//
//class JSONPathParser(val jsonPath: String) {
//    fun getSelectors(): List<JSONPathSelector> {
//        if (jsonPath.isEmpty()) {
//            throw InvalidJsonPathException(jsonPath)
//        }
//        if (jsonPath.startsWith(JSONPathConstants.ROOT_INDICATOR) == false) {
//            throw InvalidJsonPathException(jsonPath)
//        }
//        return listOf(JSONPathSelector.RootSelector()) + getSubSelectors(jsonPath.substring(1))
//    }
//
//    private fun getSubSelectors(jsonPath: String): List<JSONPathSelector> {
//        if (jsonPath.isEmpty()) {
//            return listOf()
//        }
//        if (jsonPath.length == 1) {
//            throw JSONPathParserException("Invalid JSONPath segment: $jsonPath")
//        }
//        val segmentType = when (jsonPath[0]) {
//            '.' -> JsonPathSegment.DotSegment()
//            '[' -> JsonPathSegment.IndexSegment()
//            else -> throw JSONPathParserException("Invalid JSONPath segment: $jsonPath")
//        }
//        val selectorEndSymbolIndex = when (segmentType) {
//            is JsonPathSegment.DotSegment -> {
//                // may end at '.', at '[' or with end of string
//                jsonPath.indexOfAny(listOf(".", "["), startIndex = 1).let {
//                    if (it != -1) it else jsonPath.lastIndex + 1
//                }
//            }
//
//            is JsonPathSegment.IndexSegment -> {
//                // TODO: make this more robust to more complex filters like the union selector or the filter selector, or even just keys that contain a "]"
//                jsonPath.indexOf("]", 1).let {
//                    if (it == -1) {
//                        throw JSONPathParserException("Invalid JSONPath segment: $jsonPath")
//                    } else it
//                }
//            }
//        }
//
//        val nextStartSymbol = when (segmentType) {
//            is JsonPathSegment.DotSegment -> selectorEndSymbolIndex
//            is JsonPathSegment.IndexSegment -> selectorEndSymbolIndex + 1
//        }
//
//        val selectorDetails = jsonPath.substring(1, selectorEndSymbolIndex)
//        val remainingPath = jsonPath.substring(nextStartSymbol)
//        Napier.d("selectorDetails: $selectorDetails")
//        Napier.d("consumedPath: ${jsonPath.substring(0, selectorEndSymbolIndex)}")
//        Napier.d("remaining path: $remainingPath")
//
//        val selector = when (segmentType) {
//            is JsonPathSegment.DotSegment -> when (selectorDetails) {
//                "" -> JSONPathSelector.DescendantsSelector()
//                "*" -> JSONPathSelector.DotWildCardSelector()
//                else -> JSONPathSelector.DotSelector(selectorDetails)
//            }
//
//            is JsonPathSegment.IndexSegment -> if (selectorDetails == "*") {
//                JSONPathSelector.IndexWildCardSelector()
//            } else if (selectorDetails.startsWith("?")) {
//                TODO("implement filter selector parser")
//            } else if (selectorDetails.contains(",")) {
//                TODO("implement union selector parser")
//            } else if (selectorDetails.contains(":")) {
//                TODO("implement array slice selector parser")
//            } else if (selectorDetails.startsWith("'") or selectorDetails.startsWith('"')) {
//                JSONPathSelector.IndexSelector(selectorDetails)
//            } else {
//                throw Exception("Invalid JSONPath segment: $jsonPath")
//            }
//        }
//        return listOf(selector) + getSubSelectors(remainingPath)
//    }
//}
//
//sealed interface JsonPathSegment {
//    class DotSegment : JsonPathSegment
//    class IndexSegment : JsonPathSegment
//}
//
//sealed interface JsonPathSelector {
//    // the key should be the quoted object member name or the stringified index
//    fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement>
//
//    class RootSelector : JsonPathSelector {
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            return mapOf(listOf<String>() to jsonElement)
//        }
//    }
//
//    class DotSelector(val objectMemberName: String) : JsonPathSelector {
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            return when (jsonElement) {
//                is JsonPrimitive -> mapOf()
//
//                is JsonArray -> mapOf()
//
//                is JsonObject -> jsonElement[objectMemberName]?.let {
//                    mapOf(listOf(objectMemberName) to it)
//                } ?: mapOf()
//            }
//        }
//    }
//
//    open class WildCardSelector : JsonPathSelector {
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            return when (jsonElement) {
//                is JsonPrimitive -> mapOf()
//
//                is JsonArray -> jsonElement.mapIndexed { index, it ->
//                    listOf(index.toString()) to it
//                }.toMap()
//
//                is JsonObject -> jsonElement.entries.map {
//                    listOf(it.key) to it.value
//                }.toMap()
//            }
//        }
//    }
//
//    class DotWildCardSelector : WildCardSelector()
//    class IndexWildCardSelector : WildCardSelector()
//
//    // TODO: improve this to support escaped quotes
//    class IndexSelector(
//        val memberName: String?,
//        val elementIndex: Int?,
//    ) : JsonPathSelector {
//        constructor(selector: String) : this(
//            memberName = selector.let {
//                if (it.startsWith("'") or it.startsWith('"')) {
//                    it.substring(1, it.lastIndex)
//                } else null
//            },
//            elementIndex = selector.let {
//                if (it.startsWith("'") or it.startsWith('"')) {
//                    null
//                } else it.toInt()
//            },
//        )
//
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            return when (jsonElement) {
//                is JsonPrimitive -> mapOf()
//
//                is JsonArray -> elementIndex?.let { index ->
//                    jsonElement.getOrNull(index)?.let {
//                        mapOf(listOf(index.toString()) to it)
//                    }
//                } ?: mapOf()
//
//                is JsonObject -> memberName?.let { memberName ->
//                    jsonElement.get(memberName)?.let {
//                        mapOf(listOf(memberName) to it)
//                    }
//                } ?: mapOf()
//            }
//        }
//    }
//
//    class ArraySliceSelector(val start: Int, val end: Int, val step: Int = 1) :
//        JsonPathSelector {
//
//        private val range: IntProgression
//            get() = if (start <= end) {
//                start..end step step
//            } else {
//                start downTo end step step
//            }
//
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            return when (jsonElement) {
//                is JsonPrimitive -> mapOf()
//
//                is JsonArray -> range.associateWith { index ->
//                    jsonElement.getOrNull(index)
//                }.mapKeys {
//                    listOf(it.toString())
//                }.filterNotNull()
//
//                is JsonObject -> mapOf()
//            }
//        }
//    }
//
//    class NestedDescendantsSelector : JsonPathSelector {
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            TODO("Not yet implemented")
//        }
//    }
//
//    class UnionSelector(val selectors: List<String>) : JsonPathSelector {
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            TODO("Not yet implemented")
//        }
//    }
//
//    class FilterSelector(val expression: String) : JsonPathSelector {
//        override fun invoke(jsonElement: JsonElement): Map<List<String>, JsonElement> {
//            TODO("Not yet implemented")
//        }
//    }
//}
//
//fun JsonElement.matchJsonPath(
//    jsonPath: String
//): Map<List<String>, JsonElement> {
//    var matches = mapOf(listOf<String>() to this)
//    for (selector in JSONPathParser(jsonPath).getSelectors()) {
//        matches = matches.flatMap { match ->
//            selector.invoke(match.value).map { newMatch ->
//                match.key + newMatch.key to newMatch.value
//            }.toMap().entries
//        }.toMap()
//    }
//    return matches
//}
//
//fun <K, V> Map<K, V?>.filterNotNull(): Map<K, V> {
//    val resultMap = mutableMapOf<K, V>()
//    this.entries.forEach {
//        val value = it.value
//        if (value != null) {
//            resultMap.put(it.key, value)
//        }
//    }
//    return resultMap
//}
//
//fun <K, V> Collection<Map.Entry<K, V>>.toMap(): Map<K, V> {
//    return this.associate { it.key to it.value }
//}