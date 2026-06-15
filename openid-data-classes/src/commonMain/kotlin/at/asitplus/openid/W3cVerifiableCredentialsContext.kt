package at.asitplus.openid

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class W3cVerifiableCredentialsContext(
    /**
     * VC_DATA Section 4.1
     *     The value of the @context property MUST be an ordered set where the first item is a URI with the value
     *     https://www.w3.org/2018/credentials/v1. For reference, a copy of the base context is provided in Appendix
     *     B.1 Base Context. Subsequent items in the array MUST express context information and be composed of any
     *     combination of URIs or objects. It is RECOMMENDED that each URI in the @context be one which, if
     *     dereferenced, results in a document containing machine-readable information about the @context.
     */
    private val list: List<JsonElement>,
) : List<JsonElement> by list {
    init {
        require(list.isNotEmpty()) {
            "Expected context verifiable credential context to contain at least 1 value, but got 0."
        }
        try {
            list.first().jsonPrimitive
        } catch (_: Throwable) {
            null
        }?.takeIf {
            it.isString && it.content == FIRST
        } ?: throw IllegalArgumentException(
            "Expected first context to be `https://www.w3.org/2018/credentials/v1`, but was: ${list.first()}."
        )
    }

    companion object {
        const val FIRST = "https://www.w3.org/2018/credentials/v1"
    }
}