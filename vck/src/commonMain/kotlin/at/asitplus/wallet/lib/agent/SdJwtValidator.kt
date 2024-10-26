package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.*

class SdJwtValidator {

    private val disclosures: Collection<String>
    private val valid = mutableMapOf<String, SelectiveDisclosureItem>()

    /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
    val validDisclosures: Map<String, SelectiveDisclosureItem>

    /** JSON Object with claim values reconstructed from disclosures */
    val reconstructedJsonObject: JsonObject?

    constructor(sdJwtSigned: SdJwtSigned) {
        disclosures = sdJwtSigned.rawDisclosures
        reconstructedJsonObject = sdJwtSigned.getPayloadAsJsonObject().getOrNull()?.reconstructValues()
        validDisclosures = valid.toMap()
    }

    private fun JsonObject.reconstructValues(): JsonObject = buildJsonObject {
        forEach { element ->
            val sdArray = element.toSdArray()
            val jsonObject = element.toJsonObject()
            if (sdArray != null) {
                sdArray.forEach { sdEntry -> sdEntry.toValidatedItem()?.let { processSdItem(it) } }
            } else if (jsonObject != null) {
                putIfNotEmpty(element.key, jsonObject.reconstructValues())
            } else {
                put(element.key, element.value)
            }
        }
    }

    private fun JsonObjectBuilder.processSdItem(sdItem: Pair<String, SelectiveDisclosureItem>) {
        with(sdItem.second) {
            when (val element = claimValue) {
                is JsonObject -> putIfNotEmpty(claimName, element.reconstructValues())
                else -> put(claimName, element)
            }
            valid[sdItem.first] = this
        }
    }

    private fun Map.Entry<String, JsonElement>.toJsonObject() =
        runCatching { value.jsonObject }.getOrNull()

    private fun JsonPrimitive.toValidatedItem(): Pair<String, SelectiveDisclosureItem>? =
        disclosures.firstOrNull { it.hashDisclosure() == this.content }
            ?.let { hash -> hash.toSdItem()?.let { hash to it } }

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

    private fun String.toSdItem() =
        SelectiveDisclosureItem.deserialize(decodeToByteArray(Base64UrlStrict).decodeToString()).getOrNull()

    private fun JsonObject.getSdArray(): List<JsonPrimitive>? =
        runCatching { this["_sd"]?.jsonArray }.getOrNull()
            ?.mapNotNull { runCatching { it.jsonPrimitive }.getOrNull() }

}