package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.data.JsonSerializersModuleSet
import at.asitplus.wallet.lib.data.RevocationListSubject
import at.asitplus.wallet.lib.data.vckJsonSerializer
import io.github.aakira.napier.Napier
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
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass

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
        key.safeDecodeUrlQueryComponent() to value.safeDecodeUrlQueryComponent()
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