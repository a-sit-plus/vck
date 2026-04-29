package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.JsonValueEncoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement


internal object JsonCredentialSerializer {

    val jsonElementEncoder = mutableSetOf<JsonValueEncoder>()

    fun register(function: JsonValueEncoder) {
        jsonElementEncoder += function
    }

    fun encode(value: Any): JsonElement? =
        jsonElementEncoder.firstNotNullOfOrNull { it.invoke(value) }

}

@Deprecated(
    "Use joseCompliantSerializer instead",
    ReplaceWith("joseCompliantSerializer", "at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer")
)
val vckJsonSerializer by lazy {
    Json {
        prettyPrint = false
        encodeDefaults = false
        classDiscriminator = "type"
        ignoreUnknownKeys = true
    }
}