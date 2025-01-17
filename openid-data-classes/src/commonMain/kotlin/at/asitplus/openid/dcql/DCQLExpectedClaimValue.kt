package at.asitplus.openid.dcql

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable(with = DCQLExpectedClaimValueSerializer::class)
sealed interface DCQLExpectedClaimValue {
    @JvmInline
    value class DCQLExpectedClaimStringValue(val string: String) : DCQLExpectedClaimValue

    @JvmInline
    value class DCQLExpectedClaimIntegerValue(val long: Long) : DCQLExpectedClaimValue

    @JvmInline
    value class DCQLExpectedClaimBooleanValue(val boolean: Boolean) : DCQLExpectedClaimValue
}