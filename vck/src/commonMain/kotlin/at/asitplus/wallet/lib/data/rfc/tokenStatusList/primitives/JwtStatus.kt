package at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives

import kotlinx.serialization.json.JsonObject
import kotlin.jvm.JvmInline

@JvmInline
value class JwtStatus(val value: JsonObject) {
    companion object {
        fun validate(value: JsonObject) {
            if(value.keys.isEmpty()) {
                throw IllegalArgumentException("The status (status) claim MUST specify a JSON Object that contains at least one reference to a status mechanism.")
            }
        }
    }
}