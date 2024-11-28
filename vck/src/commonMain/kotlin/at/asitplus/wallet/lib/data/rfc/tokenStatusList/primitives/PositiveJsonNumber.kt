package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.double
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class PositiveJsonNumber(val value: JsonPrimitive) {
    init {
        validate(value)
    }

    companion object {
        fun validate(value: JsonPrimitive) {
            if ((value.longOrNull ?: value.doubleOrNull) == null) {
                throw IllegalArgumentException("Value must be a JSON number.")
            }

            val isPositive = value.longOrNull?.let {
                it > 0
            } ?: (value.double > 0)

            if (!isPositive) {
                throw IllegalArgumentException("Value must be a positive JSON number.")
            }
        }
    }
}