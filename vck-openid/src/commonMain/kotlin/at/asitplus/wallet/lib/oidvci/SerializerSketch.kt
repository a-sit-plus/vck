package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.ktor.http.*
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
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
    entries.filter { (k, v) -> k.isNotEmpty() && v.isNotEmpty() }
        .associate { (k, v) -> k.safeDecodeUrlQueryComponent() to v.safeDecodeUrlQueryComponent() }.decode()

inline fun <reified T> String.decodeFromPostBody(): T = split("&")
    .associate {
        val key = it.substringBefore("=")
        val value = it.substringAfter("=", "")
        key.safeDecodeUrlQueryComponent(plusIsSpace = true) to value.safeDecodeUrlQueryComponent(plusIsSpace = true)
    }
    .decode()


inline fun <reified T> String.decodeFromUrlQuery(): T = split("&")
    .associate {
        val key = it.substringBefore("=")
        val value = it.substringAfter("=", "")
        key.safeDecodeUrlQueryComponent(plusIsSpace = true) to
                value.safeDecodeUrlQueryComponent(plusIsSpace = true)
    }
    .decode()

/**
 * Empty strings can not be decoded by [decodeURLQueryComponent], so we'll need to filter it.
 */
fun String.safeDecodeUrlQueryComponent(plusIsSpace: Boolean = false) =
    if (this.isNotEmpty()) decodeURLQueryComponent(plusIsSpace = plusIsSpace) else this

fun Parameters.formUrlEncode() = map { (k, v) -> k to v }.formUrlEncode()

inline fun <reified T> T.encodeToParameters(): Parameters =
    when (val element = json.encodeToJsonElement(this)) {
        is JsonArray -> element.mapIndexed { i, v -> i.toString() to v }
        is JsonObject -> element.map { (k, v) -> k to v }
        else -> throw SerializationException("Literals are not supported")
    }.associate { (key, value) ->
        key to if (value is JsonPrimitive) value.content else json.encodeToString(value)
    }

val json by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
        isLenient = true
        serializersModule = vckJsonSerializer.serializersModule
    }
}