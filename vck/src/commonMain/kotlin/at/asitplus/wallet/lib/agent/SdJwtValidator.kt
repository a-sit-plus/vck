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
    private val filteredClaims = listOf("_sd_alg", "...")

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
            val jsonObject = element.value as? JsonObject
            val jsonArray = element.value as? JsonArray
            if (sdArray != null) {
                sdArray.forEach { sdEntry -> sdEntry.toValidatedItem()?.let { processSdItem(it) } }
            } else if (jsonObject != null) {
                putIfNotEmpty(element.key, jsonObject.reconstructValues())
            } else if (jsonArray != null) {
                putIfNotEmpty(element.key, reconstructJsonArray(jsonArray))
            } else {
                if (element.key !in filteredClaims) {
                    put(element.key, element.value)
                }
            }
        }
    }

    private fun reconstructJsonArray(jsonArray: JsonArray) = buildJsonArray {
        jsonArray.forEach { entry ->
            if (entry is JsonObject) {
                entry.asArrayDisclosure()?.let {
                    it.toValidatedItem()?.let { processSdItem(it) }
                } ?: addIfNotEmpty(entry.reconstructValues())
            } else {
                add(entry)
            }
        }
    }

    private fun JsonObject.asArrayDisclosure() =
        if (this.size == 1 && this.containsKey("...") && this["..."] is JsonPrimitive)
            this["..."] as JsonPrimitive
        else null

    private fun JsonArrayBuilder.processSdItem(sdItem: Pair<String, SelectiveDisclosureItem>) {
        with(sdItem.second) {
            when (claimValue) {
                is JsonObject -> add(claimValue.reconstructValues())
                else -> add(claimValue)
            }
            valid[sdItem.first] = this
        }
    }

    private fun JsonObjectBuilder.processSdItem(sdItem: Pair<String, SelectiveDisclosureItem>) {
        with(sdItem.second) {
            when (val element = claimValue) {
                is JsonObject -> claimName?.let { putIfNotEmpty(it, element.reconstructValues()) }
                else -> claimName?.let { put(it, element) }
            }
            valid[sdItem.first] = this
        }
    }

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

    private fun JsonObjectBuilder.putIfNotEmpty(key: String, it: JsonArray) {
        if (!it.isEmpty()) put(key, it)
    }

    private fun JsonArrayBuilder.addIfNotEmpty(it: JsonObject) {
        if (!it.isEmpty()) add(it)
    }

    private fun String.toSdItem() =
        SelectiveDisclosureItem.deserialize(decodeToByteArray(Base64UrlStrict).decodeToString()).getOrNull()

}
