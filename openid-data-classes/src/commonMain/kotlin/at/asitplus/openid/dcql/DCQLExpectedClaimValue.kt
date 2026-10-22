package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

@Serializable(with = DCQLExpectedClaimValueSerializer::class)
sealed interface DCQLExpectedClaimValue {
    @JvmInline
    value class StringValue(val string: String) : DCQLExpectedClaimValue

    @JvmInline
    value class IntegerValue(val long: Long) : DCQLExpectedClaimValue

    @JvmInline
    value class BooleanValue(val boolean: Boolean) : DCQLExpectedClaimValue
}

/**
 * Whether [primitive] matches this expected value. OpenID4VP 1.0, 6.3: the type and value of the claim both have to
 * match exactly.
 */
internal fun DCQLExpectedClaimValue.matches(primitive: JsonPrimitive): Boolean = when (this) {
    is DCQLExpectedClaimValue.StringValue -> primitive.isString && primitive.content == string
    is DCQLExpectedClaimValue.BooleanValue -> !primitive.isString && primitive.booleanOrNull == boolean
    is DCQLExpectedClaimValue.IntegerValue -> !primitive.isString && primitive.longOrNull == long
}
