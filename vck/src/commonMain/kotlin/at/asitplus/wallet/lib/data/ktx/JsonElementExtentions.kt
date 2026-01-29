package at.asitplus.wallet.lib.data.ktx

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * SPDX-License-Identifier: Apache-2.0
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Extracts the `id` field from a [JsonElement].
 *
 * This extension function safely retrieves the value of the `id` property as a string
 * from a [JsonObject]. If the [JsonElement] is not an object, the function returns `null`
 * without throwing an exception.
 *
 * @return The string value of the `id` field if all conditions are met:
 *         - The [JsonElement] is a [JsonObject]
 *         - The `id` field exists in the object
 *         - The `id` field value is a [JsonPrimitive]
 *
 *         Returns `null` if:
 *         - The [JsonElement] is not a [JsonObject] (e.g., array, primitive, or null)
 *         - The `id` field does not exist in the object
 *         - The `id` field is not a [JsonPrimitive] (e.g., it's an object or array)
 *
 * Example usage:
 * ```kotlin
 * val jsonObject = Json.parseToJsonElement("""{"id": "123", "name": "John"}""")
 * val id = jsonObject.extractId() // Returns "123"
 *
 * val jsonArray = Json.parseToJsonElement("""["item1", "item2"]""")
 * val id = jsonArray.extractId() // Returns null
 * ```
 */
fun JsonElement.extractId(): String? {
    return if (this is JsonObject) {
        this.jsonObject["id"]?.jsonPrimitive?.content
    } else {
        null
    }
}
