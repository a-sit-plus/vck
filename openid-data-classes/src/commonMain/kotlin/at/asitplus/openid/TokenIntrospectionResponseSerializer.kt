package at.asitplus.openid

import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.jsonObject

/**
 * Keeps [TokenIntrospectionResponse.additionalClaims] flat on the wire, as service-specific names are
 * "top-level members of this JSON object" ([RFC 7662 2.2](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2)),
 * whereas the generated serializer nests them under [ADDITIONAL_CLAIMS]:
 *
 * ```
 * wire:      {"active":true,"sub":"x","given_name":"Erika"}
 * generated: {"active":true,"sub":"x","additional_claims":{"given_name":"Erika"}}
 * ```
 */
object TokenIntrospectionResponseSerializer :
    JsonTransformingSerializer<TokenIntrospectionResponse>(TokenIntrospectionResponse.generatedSerializer()) {

    /** Name of [TokenIntrospectionResponse.additionalClaims] in the generated serializer only, never on the wire. */
    internal const val ADDITIONAL_CLAIMS = "additional_claims"

    /** Serial names of all properties of [TokenIntrospectionResponse] except [ADDITIONAL_CLAIMS]. */
    private val propertyNames by lazy { descriptor.elementNames.toSet() - ADDITIONAL_CLAIMS }

    private fun isProperty(name: String) = name in propertyNames

    /** Wire to generated: moves every member that has no property of its own into [ADDITIONAL_CLAIMS]. */
    override fun transformDeserialize(element: JsonElement): JsonElement {
        val response = element as? JsonObject ?: return element
        val properties = response.filterKeys { isProperty(it) }
        val additionalClaims = response.filterKeys { !isProperty(it) }
        return if (additionalClaims.isEmpty()) JsonObject(properties)
        else JsonObject(properties + (ADDITIONAL_CLAIMS to JsonObject(additionalClaims)))
    }

    /**
     * Generated to wire: lifts the members of [ADDITIONAL_CLAIMS] to the top level, dropping those that have the name
     * of a property, so that the property wins.
     */
    override fun transformSerialize(element: JsonElement): JsonElement {
        val response = element.jsonObject
        val properties = response.filterKeys { isProperty(it) }
        val additionalClaims = (response[ADDITIONAL_CLAIMS] as? JsonObject).orEmpty()
            .filterKeys { !isProperty(it) }
        return JsonObject(properties + additionalClaims)
    }
}
