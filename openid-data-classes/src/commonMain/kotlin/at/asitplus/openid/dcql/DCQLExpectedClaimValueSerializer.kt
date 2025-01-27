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
            is DCQLExpectedClaimValue.BooleanValue -> JsonPrimitive(it.boolean)
            is DCQLExpectedClaimValue.IntegerValue -> JsonPrimitive(it.long)
            is DCQLExpectedClaimValue.StringValue -> JsonPrimitive(it.string)
        }
    },

    decodeAs = {
        when {
            it.booleanOrNull != null -> DCQLExpectedClaimValue.BooleanValue(it.boolean)
            it.longOrNull != null -> DCQLExpectedClaimValue.IntegerValue(it.long)
            it.isString -> DCQLExpectedClaimValue.StringValue(it.content)
            else -> throw IllegalArgumentException("Value is not a valid expected claim value.")
        }
    }
)