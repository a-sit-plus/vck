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

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement

/**
 * VC spec leaves the representation of a single credential open to implementations.
 * We decided to make a "generic" one, i.e. with custom [name], [value] and [mimeType].
 */
@Serializable
@SerialName("AtomicAttribute2023")
data class AtomicAttribute2023(
    override val id: String,

    @SerialName("name")
    val name: String,

    @SerialName("value")
    val value: String,

    @SerialName("mime-type")
    val mimeType: String,
) : CredentialSubject() {

    constructor(id: String, name: String, value: String) : this(id, name, value, "application/text")

}

/**
 * Converts this [AtomicAttribute2023] to a [JsonElement] using kotlinx.serialization.
 *
 * @return The JSON representation of this attribute
 * @throws kotlinx.serialization.SerializationException if serialization fails
 */
fun AtomicAttribute2023.toJsonElement(): JsonElement =
    Json.encodeToJsonElement(AtomicAttribute2023.serializer(), this)