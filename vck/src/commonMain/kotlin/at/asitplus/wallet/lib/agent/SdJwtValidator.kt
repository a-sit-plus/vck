package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.agent.SdJwtCreator.NAME_SD
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem.Companion.hashDisclosure
import at.asitplus.wallet.lib.jws.SdJwtSigned
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.*

/**
 * Decodes a [SdJwtSigned], by substituting all blinded disclosure values (inside `_sd` elements of the payload)
 * with the claims of the disclosures appended to the SD-JWT (by a `~`).
 *
 * See [Selective Disclosure for JWTs (SD-JWT)](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-13.html)
 */
class SdJwtValidator(sdJwtSigned: SdJwtSigned) {

    private val disclosures: Collection<String> = sdJwtSigned.rawDisclosures
    private val _validDisclosures = mutableMapOf<String, SelectiveDisclosureItem>()

    /** Per 7.1 Verification of the SD-JWT in the spec */
    private val filteredClaims = listOf("_sd_alg", "...")

    /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
    val validDisclosures: Map<String, SelectiveDisclosureItem>

    /** JSON Object with claim values reconstructed from disclosures */
    val reconstructedJsonObject: JsonObject?

    init {
        reconstructedJsonObject = sdJwtSigned.getPayloadAsJsonObject().getOrNull()?.reconstructValues()
        validDisclosures = _validDisclosures.toMap()
    }

    private fun JsonObject.reconstructValues(): JsonObject = buildJsonObject {
        forEach { element ->
            val sdArray = element.asSdArray()
            val jsonObject = element.value as? JsonObject
            val jsonArray = element.value as? JsonArray
            if (sdArray != null) {
                sdArray.forEach { processSdItem(it) }
            } else if (jsonObject != null) {
                putIfNotEmpty(element.key, jsonObject.reconstructValues())
            } else if (jsonArray != null) {
                putIfNotEmpty(element.key, jsonArray.reconstructValues())
            } else {
                if (element.key !in filteredClaims) {
                    put(element.key, element.value)
                }
            }
        }
    }

    private fun JsonArray.reconstructValues() = buildJsonArray {
        forEach { element ->
            val sdArrayEntry = element.asArrayDisclosure()
            val jsonObject = element as? JsonObject
            if (sdArrayEntry != null) {
                processSdItem(sdArrayEntry)
            } else if (jsonObject != null) {
                addIfNotEmpty(element.reconstructValues())
            } else {
                add(element)
            }
        }
    }

    private fun JsonElement.asArrayDisclosure() =
        if (this is JsonObject && this.size == 1 && this["..."] is JsonPrimitive)
            this["..."] as JsonPrimitive
        else null

    private fun JsonArrayBuilder.processSdItem(disclosure: JsonPrimitive) {
        disclosure.toValidatedItem()?.let { sdItem ->
            when (sdItem.claimValue) {
                is JsonObject -> add(sdItem.claimValue.reconstructValues())
                else -> add(sdItem.claimValue)
            }
        }
    }

    private fun JsonObjectBuilder.processSdItem(disclosure: JsonPrimitive) {
        disclosure.toValidatedItem()?.let { sdItem ->
            when (val element = sdItem.claimValue) {
                is JsonObject -> sdItem.claimName?.let { putIfNotEmpty(it, element.reconstructValues()) }
                else -> sdItem.claimName?.let { put(it, element) }
            }
        }
    }

    private fun JsonPrimitive.toValidatedItem(): SelectiveDisclosureItem? =
        disclosures.firstOrNull { it.hashDisclosure() == this.content }?.let { disclosure ->
            disclosure.toSdItem()
                ?.also { _validDisclosures[disclosure] = it }
        }

    private fun Map.Entry<String, JsonElement>.asSdArray(): List<JsonPrimitive>? =
        if (key == NAME_SD) {
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
