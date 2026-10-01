package at.asitplus.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.ktor.http.*
import io.ktor.http.formUrlEncode
import io.ktor.util.*
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerializationStrategy
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.StructureKind
import kotlinx.serialization.encoding.CompositeDecoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonUnquotedLiteral
import kotlinx.serialization.serializer

/**
 * Name/value pairs of an `application/x-www-form-urlencoded` payload, i.e. a URL query, a URL fragment, or a POST body,
 * as used all over OAuth 2.0, OpenID4VCI and OpenID4VP.
 *
 * Names and values are always **decoded**, i.e. free of percent-encoding. The percent-encoded wire format is a [String]
 * and is produced by [formUrlEncode] and consumed by [decodeFromFormUrlEncoded].
 *
 * Note that this is a plain [Map], so a name may carry only a single value. Repeated names, which neither OAuth 2.0 nor
 * OpenID4VP make use of, collapse to their last occurrence.
 */
typealias FormParameters = Map<String, String>

/**
 * Serializes [this] into [FormParameters], to be transmitted as a URL query or a POST body.
 *
 * Members that are not JSON primitives (objects and arrays, e.g. `dcql_query`) are serialized to their compact JSON
 * representation, which is what OpenID4VP and OpenID4VCI prescribe for those parameters.
 *
 * @throws SerializationException if [this] does not serialize to a JSON object or array, i.e. if it is a literal
 */
inline fun <reified T> T.encodeToParameters(): FormParameters =
    encodeToParameters(jsonForParameters.serializersModule.serializer<T>())

/** Variant of [encodeToParameters] taking an explicit [serializer], for use without reified type information. */
fun <T> T.encodeToParameters(serializer: SerializationStrategy<T>): FormParameters =
    jsonForParameters.encodeToJsonElement(serializer, this).encodeToParameters()

/** Serializes [this] directly to the percent-encoded wire format, i.e. [encodeToParameters] plus [formUrlEncode]. */
inline fun <reified T> T.encodeToFormUrlEncoded(): String = encodeToParameters().formUrlEncode()

/** Percent-encodes [this] into the `application/x-www-form-urlencoded` wire format. */
fun FormParameters.formUrlEncode(): String = map { (k, v) -> k to v }.formUrlEncode()

/**
 * Deserializes [FormParameters] into [T].
 *
 * Values are interpreted by the shape of [T]: members declared as strings keep their value verbatim, all others are
 * read as JSON, so that objects, arrays, numbers and booleans survive the round-trip through [encodeToParameters].
 * For polymorphic types, select a concrete deserializer first so its descriptor describes the form fields.
 *
 * @throws SerializationException if the parameters do not describe a valid [T]
 */
inline fun <reified T> FormParameters.decode(): T = decode(jsonForParameters.serializersModule.serializer<T>())

/** Variant of [decode] taking an explicit [deserializer], for use without reified type information. */
fun <T> FormParameters.decode(deserializer: DeserializationStrategy<T>): T =
    jsonForParameters.decodeFromJsonElement(deserializer, toJsonObject(deserializer.descriptor))

/**
 * Deserializes the percent-encoded `application/x-www-form-urlencoded` wire format in [this] into [T].
 *
 * Accepts the payload only, i.e. a POST body, a URL query or a URL fragment, but *not* a full URL: use
 * [Url.decodeFromQuery] or [Url.decodeFromFragment] for those, which strip the parts that are not parameters.
 *
 * @throws SerializationException if the parameters do not describe a valid [T]
 */
inline fun <reified T> String.decodeFromFormUrlEncoded(): T =
    decodeFromFormUrlEncoded(jsonForParameters.serializersModule.serializer<T>())

/** Variant of [decodeFromFormUrlEncoded] taking an explicit [deserializer], for use without reified type information. */
fun <T> String.decodeFromFormUrlEncoded(deserializer: DeserializationStrategy<T>): T =
    toFormParameters().decode(deserializer)

/**
 * Splits the percent-encoded `application/x-www-form-urlencoded` payload in [this] into its decoded [FormParameters].
 *
 * Names without a value (`&foo&`) are dropped, since there is nothing to deserialize from them.
 */
fun String.toFormParameters(): FormParameters = parseQueryString(this).flattenEntries().toMap()

/** Deserializes the query of [this] into [T], e.g. the `code` of an authn response in `https://example.com?code=...`. */
inline fun <reified T> Url.decodeFromQuery(): T = encodedQuery.decodeFromFormUrlEncoded()

/**
 * Deserializes the fragment of [this] into [T], e.g. the parameters of an authn response in
 * `https://example.com#vp_token=...`.
 */
inline fun <reified T> Url.decodeFromFragment(): T = encodedFragment.decodeFromFormUrlEncoded()

/**
 * Deserializes the fragment of [this] into [T], falling back to the query if [this] carries no fragment.
 *
 * Returns `null` if [this] carries neither, so that callers can tell a URL that transports no parameters at all from
 * one whose parameters fail to deserialize, which throws.
 */
inline fun <reified T> Url.decodeFromFragmentOrQuery(): T? = when {
    encodedFragment.isNotEmpty() -> decodeFromFragment()
    encodedQuery.isNotEmpty() -> decodeFromQuery()
    else -> null
}

/**
 * Maps [FormParameters] onto the [JsonObject] they describe, guided by [descriptor]:
 * members declared as strings keep their content verbatim, all others are read as JSON.
 * Unknown object members are ignored before their values are parsed; map keys remain unrestricted.
 */
internal fun FormParameters.toJsonObject(descriptor: SerialDescriptor): JsonObject = JsonObject(
    buildMap {
        this@toJsonObject.forEach { (name, value) ->
            if ((descriptor.kind == StructureKind.CLASS || descriptor.kind == StructureKind.OBJECT)
                && descriptor.getElementIndex(name) == CompositeDecoder.UNKNOWN_NAME
            ) return@forEach
            value.toJsonElement(descriptor.isStringElement(name))?.let { put(name, it) }
        }
    }
)

/** Returns `null` for a value that carries nothing to deserialize, so that callers can drop that member. */
private fun String.toJsonElement(isString: Boolean): JsonElement? = when {
    // members declared as strings keep their content verbatim, even if that content happens to be JSON itself,
    // e.g. `wallet_metadata` of `at.asitplus.openid.RequestObjectParameters`
    isString -> JsonPrimitive(this)
    isEmpty() -> null // an empty value is not a JSON literal, and there is no member to build from it
    startsWith('{') -> jsonForParameters.decodeFromString<JsonObject>(this)
    startsWith('[') -> jsonForParameters.decodeFromString<JsonArray>(this)
    // unquoted, so it may deserialize as any type; this is what `jsonForParameters` needs to be lenient for
    else -> JsonUnquotedLiteral(this)
}

/** Serializes a [JsonObject] to its members, and a [JsonArray] to its indices, as their compact JSON representation. */
private fun JsonElement.encodeToParameters(): FormParameters = when (this) {
    is JsonArray -> mapIndexed { index, value -> index.toString() to value }
    is JsonObject -> map { (name, value) -> name to value }
    else -> throw SerializationException("Literals are not supported")
}.associate { (name, value) ->
    name to if (value is JsonPrimitive) value.content else jsonForParameters.encodeToString(value)
}

/** Whether the member serialized as [name] is a string, for descriptors that have members at all. */
fun SerialDescriptor.isStringElement(name: String): Boolean = catchingUnwrapped {
    getElementIndex(name).let {
        it != CompositeDecoder.UNKNOWN_NAME && getElementDescriptor(it).kind == PrimitiveKind.STRING
    }
}.getOrElse { false }

/**
 * Empty strings can not be decoded by [decodeURLQueryComponent], so we'll need to filter it.
 */
fun String.safeDecodeUrlQueryComponent(plusIsSpace: Boolean = false) =
    if (this.isNotEmpty()) decodeURLQueryComponent(plusIsSpace = plusIsSpace) else this

/**
 * [Json] instance for [FormParameters]: the important bit here compared to other instances is `isLenient = true`, to be
 * able to decode the unquoted values of URL query parameters.
 */
val jsonForParameters by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = true
        explicitNulls = false
        ignoreUnknownKeys = true
        isLenient = true
        serializersModule = joseCompliantSerializer.serializersModule
    }
}
