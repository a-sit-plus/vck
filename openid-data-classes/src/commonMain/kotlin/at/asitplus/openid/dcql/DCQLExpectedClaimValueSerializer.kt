package at.asitplus.openid.dcql

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.long
import kotlinx.serialization.json.longOrNull

object DCQLExpectedClaimValueSerializer : KSerializer<DCQLExpectedClaimValue> by TransformingSerializerTemplate<DCQLExpectedClaimValue, JsonPrimitive>(
    parent = JsonPrimitive.serializer(),
    encodeAs = {
        when (it) {
            is DCQLExpectedClaimValue.DCQLExpectedClaimBooleanValue -> JsonPrimitive(it.boolean)
            is DCQLExpectedClaimValue.DCQLExpectedClaimIntegerValue -> JsonPrimitive(it.long)
            is DCQLExpectedClaimValue.DCQLExpectedClaimStringValue -> JsonPrimitive(it.string)
        }
    },

    decodeAs = {
        when {
            it.booleanOrNull != null -> DCQLExpectedClaimValue.DCQLExpectedClaimBooleanValue(it.boolean)
            it.longOrNull != null -> DCQLExpectedClaimValue.DCQLExpectedClaimIntegerValue(it.long)
            it.isString -> DCQLExpectedClaimValue.DCQLExpectedClaimStringValue(it.content)
            else -> throw IllegalArgumentException("Value is not a valid expected claim value.")
        }
    }
)