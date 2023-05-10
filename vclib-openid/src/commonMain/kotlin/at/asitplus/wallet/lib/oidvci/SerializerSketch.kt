package at.asitplus.wallet.lib.oidvci

import io.ktor.http.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

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
    .associate { it.split("=")[0].decodeURLQueryComponent() to it.split("=")[1].decodeURLQueryComponent() }
    .decode()

fun Parameters.formUrlEncode() = map { (k, v) -> k to v }.formUrlEncode()
inline fun <reified T> T.encodeToParameters(): Parameters =
    when (val tmp = json.encodeToJsonElement(this)) {
        is JsonArray -> tmp.mapIndexed { i, v -> i.toString() to v }
        is JsonObject -> tmp.map { (k, v) -> k to v }
        else -> throw SerializationException("Literals are not supported")
    }.associate { (k, v) -> k to if (v is JsonPrimitive) v.content else json.encodeToString(v) }

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