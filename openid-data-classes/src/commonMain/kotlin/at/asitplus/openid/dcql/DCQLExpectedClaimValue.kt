package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = DCQLExpectedClaimValueSerializer::class)
sealed interface DCQLExpectedClaimValue {
    @JvmInline
    value class StringValue(val string: String) : DCQLExpectedClaimValue

    @JvmInline
    value class IntegerValue(val long: Long) : DCQLExpectedClaimValue

    @JvmInline
    value class BooleanValue(val boolean: Boolean) : DCQLExpectedClaimValue
}