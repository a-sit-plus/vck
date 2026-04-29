package at.asitplus.wallet.lib.data

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Adding an extension to convert AtomicAttribute2023 to a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.decodeFromJsonElement

/**
 * VC spec leaves the representation of a single credential open to implementations.
 * We decided to make a "generic" one, i.e. with custom [name], [value] and [mimeType].
 */
@Serializable
data class AtomicAttribute2023(
    @SerialName("id")
    val id: String,

    @SerialName("name")
    val name: String,

    @SerialName("value")
    val value: String,

    @SerialName("mime-type")
    val mimeType: String,
) {

    constructor(id: String, name: String, value: String) : this(id, name, value, "application/text")

    companion object {

        /**
         * Converts a [JsonElement] into a [AtomicAttribute2023] using kotlinx.serialization.
         *
         * @throws kotlinx.serialization.SerializationException if serialization fails
         */
        fun fromJsonElement(input: JsonElement): AtomicAttribute2023 =
            joseCompliantSerializer.decodeFromJsonElement(input)

    }

}

/**
 * Converts this [AtomicAttribute2023] to a [JsonElement] using kotlinx.serialization.
 *
 * @return The JSON representation of this attribute
 * @throws kotlinx.serialization.SerializationException if serialization fails
 */
fun AtomicAttribute2023.toJsonElement(): JsonElement =
    joseCompliantSerializer.encodeToJsonElement(AtomicAttribute2023.serializer(), this)
