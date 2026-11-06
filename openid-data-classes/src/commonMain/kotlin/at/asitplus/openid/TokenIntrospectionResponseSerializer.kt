package at.asitplus.openid

import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.jsonObject

/**
 * Serializes [TokenIntrospectionResponse.additionalClaims] as top-level members of the response
 * ([RFC 7662 2.2](https://datatracker.ietf.org/doc/html/rfc7662#section-2.2)), and parses every member without a
 * property of its own into it.
 */
object TokenIntrospectionResponseSerializer :
    JsonTransformingSerializer<TokenIntrospectionResponse>(TokenIntrospectionResponse.generatedSerializer()) {

    /** Name of [TokenIntrospectionResponse.additionalClaims] in the generated serializer only, never on the wire. */
    internal const val ADDITIONAL_CLAIMS = "additional_claims"

    private val typedMembers by lazy { descriptor.elementNames.toSet() - ADDITIONAL_CLAIMS }

    override fun transformDeserialize(element: JsonElement): JsonElement {
        val members = element as? JsonObject ?: return element
        val additionalClaims = members.filterKeys { it !in typedMembers }
        val typed = members.filterKeys { it in typedMembers }
        return if (additionalClaims.isEmpty()) JsonObject(typed)
        else JsonObject(typed + (ADDITIONAL_CLAIMS to JsonObject(additionalClaims)))
    }

    override fun transformSerialize(element: JsonElement): JsonElement {
        val members = element.jsonObject
        val additionalClaims = (members[ADDITIONAL_CLAIMS] as? JsonObject)
            ?.filterKeys { it !in typedMembers }
            .orEmpty()
        return JsonObject(members - ADDITIONAL_CLAIMS + additionalClaims)
    }
}
