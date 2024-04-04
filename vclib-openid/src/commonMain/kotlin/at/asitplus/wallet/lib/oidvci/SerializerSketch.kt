package at.asitplus.wallet.lib.oidvci

import io.ktor.http.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonUnquotedLiteral
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement

typealias Parameters = Map<String, String>

@OptIn(ExperimentalSerializationApi::class)
inline fun <reified T> Parameters.decode(): T =
    json.decodeFromJsonElement<T>(JsonObject(entries.associate { (k, v) ->
        k to when (v[0]) {
            '{' -> json.decodeFromString<JsonObject>(v)
            '[' -> json.decodeFromString<JsonArray>(v)
            else -> JsonUnquotedLiteral(v)  //no quoted → can be any type for deserializing. requires lenient parsing
        }
    }))

inline fun <reified T> Parameters.decodeFromUrlQuery(): T =
    entries.associate { (k, v) -> k.decodeURLQueryComponent() to v.decodeURLQueryComponent() }.decode()

inline fun <reified T> String.decodeFromPostBody(): T = split("&")
    .associate {
        it.substringBefore("=").decodeURLQueryComponent() to
                it.substringAfter("=", "").decodeURLQueryComponent()
    }
    .decode()

inline fun <reified T> String.decodeFromUrlQuery(): T = split("&")
    .associate {
        it.substringBefore("=").decodeURLQueryComponent(plusIsSpace = true) to
                it.substringAfter("=", "").decodeURLQueryComponent(plusIsSpace = true)
    }
    .decode()

fun Parameters.formUrlEncode() = map { (k, v) -> k to v }.formUrlEncode()

inline fun <reified T> T.encodeToParameters(): Parameters =
    when (val element = json.encodeToJsonElement(this)) {
        is JsonArray -> element.mapIndexed { i, v -> i.toString() to v }
        is JsonObject -> element.map { (k, v) -> k to v }
        else -> throw SerializationException("Literals are not supported")
    }.associate { (key, value) ->
        key to if (value is JsonPrimitive) value.content else json.encodeToString(value)
    }

@OptIn(ExperimentalSerializationApi::class)
val json by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
        isLenient = true
    }
}