@file:Suppress("DEPRECATION")

package at.asitplus.wallet.lib.oidvci

import at.asitplus.openid.FormParameters
import at.asitplus.openid.decode as decodeMoved
import at.asitplus.openid.decodeFromFormUrlEncoded as decodeFromFormUrlEncodedMoved
import at.asitplus.openid.encodeToParameters as encodeToParametersMoved
import at.asitplus.openid.formUrlEncode as formUrlEncodeMoved
import at.asitplus.openid.isStringElement as isStringElementMoved
import at.asitplus.openid.jsonForParameters as jsonForParametersMoved
import at.asitplus.openid.safeDecodeUrlQueryComponent as safeDecodeUrlQueryComponentMoved
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.json.Json
import kotlinx.serialization.serializer

/**
 * Compatibility layer for the `application/x-www-form-urlencoded` (de)serialization of OAuth 2.0, OpenID4VCI and
 * OpenID4VP parameters, which moved to `at.asitplus.openid` in `openid-data-classes`, next to the parameter classes it
 * encodes. Every declaration here forwards to its replacement and will be removed.
 */
private const val MOVED = "Moved to at.asitplus.openid in openid-data-classes"

/** Names and values of an `application/x-www-form-urlencoded` payload. */
@Deprecated(MOVED, ReplaceWith("FormParameters", "at.asitplus.openid.FormParameters"))
typealias Parameters = FormParameters

@Deprecated(MOVED, ReplaceWith("encodeToParameters<T>()", "at.asitplus.openid.encodeToParameters"))
inline fun <reified T> T.encodeToParameters(): FormParameters =
    encodeToParametersMoved(jsonForParametersMoved.serializersModule.serializer<T>())

@Deprecated(MOVED, ReplaceWith("formUrlEncode()", "at.asitplus.openid.formUrlEncode"))
fun FormParameters.formUrlEncode(): String = formUrlEncodeMoved()

@Deprecated(MOVED, ReplaceWith("decode(deserializer)", "at.asitplus.openid.decode"))
fun <T> FormParameters.decode(deserializer: DeserializationStrategy<T>): T = decodeMoved(deserializer)

@Deprecated(MOVED, ReplaceWith("decode<T>()", "at.asitplus.openid.decode"))
inline fun <reified T> FormParameters.decode(): T =
    decodeMoved(jsonForParametersMoved.serializersModule.serializer<T>())

/**
 * Deserializes already-decoded [FormParameters] into [T], decoding percent-encoding once more.
 *
 * Deprecated because its receiver is decoded in nearly all call sites (e.g. [io.ktor.http.Url.parameters]), so that
 * this decodes a second time and mangles values containing `%`. Use [at.asitplus.openid.decode] for parameters that are
 * already decoded, or [at.asitplus.openid.decodeFromQuery] to get them from a URL in the first place.
 */
@Deprecated(
    "Double-decodes parameters that are already decoded",
    ReplaceWith("decode<T>()", "at.asitplus.openid.decode")
)
inline fun <reified T> FormParameters.decodeFromUrlQuery(): T =
    entries.filter { (k, v) -> k.isNotEmpty() && v.isNotEmpty() }
        .associate { (k, v) -> k.safeDecodeUrlQueryComponentMoved() to v.safeDecodeUrlQueryComponentMoved() }
        .decodeMoved(jsonForParametersMoved.serializersModule.serializer<T>())

/** Deserializes the percent-encoded parameters of a POST body into [T]. */
@Deprecated(
    "POST body and URL query share one encoding",
    ReplaceWith("decodeFromFormUrlEncoded<T>()", "at.asitplus.openid.decodeFromFormUrlEncoded")
)
inline fun <reified T> String.decodeFromPostBody(): T = decodeFromFormUrlEncodedMoved()

/**
 * Deserializes a percent-encoded URL query into [T].
 *
 * Deprecated because the name invites passing a complete URL, of which the first parameter would then silently be
 * dropped: use [at.asitplus.openid.decodeFromQuery] for a URL, and [at.asitplus.openid.decodeFromFormUrlEncoded] for a
 * bare query string.
 */
@Deprecated(
    "POST body and URL query share one encoding",
    ReplaceWith("decodeFromFormUrlEncoded<T>()", "at.asitplus.openid.decodeFromFormUrlEncoded")
)
inline fun <reified T> String.decodeFromUrlQuery(): T = decodeFromFormUrlEncodedMoved()

/** Whether the member serialized as [name] is a string, for descriptors that have members at all. */
@Deprecated(MOVED, ReplaceWith("isStringElement(name)", "at.asitplus.openid.isStringElement"))
fun SerialDescriptor.isStringElement(name: String): Boolean = isStringElementMoved(name)

/** Empty strings can not be decoded by [io.ktor.http.decodeURLQueryComponent], so we'll need to filter it. */
@Deprecated(
    MOVED,
    ReplaceWith("safeDecodeUrlQueryComponent(plusIsSpace)", "at.asitplus.openid.safeDecodeUrlQueryComponent")
)
fun String.safeDecodeUrlQueryComponent(plusIsSpace: Boolean = false): String =
    safeDecodeUrlQueryComponentMoved(plusIsSpace)

/** [Json] instance for [FormParameters], lenient so that it can decode the unquoted values of URL query parameters. */
@Deprecated(MOVED, ReplaceWith("jsonForParameters", "at.asitplus.openid.jsonForParameters"))
val jsonForParameters: Json get() = jsonForParametersMoved
