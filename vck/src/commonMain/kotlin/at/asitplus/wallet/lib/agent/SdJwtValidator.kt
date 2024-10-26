package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.*

class SdJwtValidator(
    private val disclosures: List<String>
) {

    fun reconstructJson(
        input: JsonObject,
    ): JsonObject = buildJsonObject {
        input.forEach { inputElement ->
            inputElement.toSdArray()?.forEach { sdEntry ->
                sdEntry.toValidatedItem()?.let { sdItem ->
                    processSdItem(sdItem)
                }
            } ?: run {
                inputElement.toJsonObject()?.let { nested ->
                    putIfNotEmpty(inputElement.key, reconstructJson(nested))
                }
            }
        }
    }

    private fun JsonObjectBuilder.processSdItem(
        sdItem: SelectiveDisclosureItem,
    ) {
        when (val element = sdItem.claimValue) {
            is JsonObject -> putIfNotEmpty(sdItem.claimName, reconstructJson(element))
            else -> put(sdItem.claimName, element)
        }
    }

    private fun Map.Entry<String, JsonElement>.toJsonObject() =
        runCatching { value.jsonObject }.getOrNull()

    private fun JsonPrimitive.toValidatedItem(): SelectiveDisclosureItem? =
        disclosures.matchDisclosureHash(this)?.toSdItem()

    private fun Map.Entry<String, JsonElement>.toSdArray(): List<JsonPrimitive>? =
        if (key == "_sd") {
            kotlin.runCatching { value.jsonArray }.getOrNull()
                ?.mapNotNull { runCatching { it.jsonPrimitive }.getOrNull() }
        } else {
            null
        }

    private fun JsonObjectBuilder.putIfNotEmpty(key: String, it: JsonObject) {
        if (!it.isEmpty()) put(key, it)
    }

    private fun List<String>.matchDisclosureHash(sdEntry: JsonPrimitive) =
        firstOrNull { it.hashDisclosure() == sdEntry.content }

    private fun String.toSdItem() =
        SelectiveDisclosureItem.deserialize(decodeToByteArray(Base64UrlStrict).decodeToString()).getOrNull()

    private fun JsonObject.getSdArray(): List<JsonPrimitive>? =
        runCatching { this["_sd"]?.jsonArray }.getOrNull()
            ?.mapNotNull { runCatching { it.jsonPrimitive }.getOrNull() }

}