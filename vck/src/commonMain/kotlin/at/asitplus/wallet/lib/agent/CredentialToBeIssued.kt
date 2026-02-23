package at.asitplus.wallet.lib.agent

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: VcJwt subject type changed from CredentialSubject to JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.CredentialSubject
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.jws.JwsHeaderModifierFun
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.time.Instant

sealed class CredentialToBeIssued {
    abstract val expiration: Instant
    abstract val scheme: ConstantIndex.CredentialScheme
    abstract val subjectPublicKey: CryptoPublicKey
    abstract val userInfo: OidcUserInfoExtended

    data class VcJwt(
        val subject: JsonElement,
        override val expiration: Instant,
        override val scheme: ConstantIndex.CredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
        override val userInfo: OidcUserInfoExtended,
    ) : CredentialToBeIssued() {
        @Deprecated(
            message = "Use constructor with JsonElement subject instead",
            replaceWith = ReplaceWith("VcJwt(subject as JsonElement, expiration, scheme, subjectPublicKey, userInfo)"),
            level = DeprecationLevel.ERROR
        )
        constructor(
            subject: CredentialSubject,
            expiration: Instant,
            scheme: ConstantIndex.CredentialScheme,
            subjectPublicKey: CryptoPublicKey,
            userInfo: OidcUserInfoExtended,
        ) : this(
            subject = Json.encodeToJsonElement(subject),
            expiration = expiration,
            scheme = scheme,
            subjectPublicKey = subjectPublicKey,
            userInfo = userInfo
        )
    }

    data class VcSd(
        val claims: Collection<ClaimToBeIssued>,
        override val expiration: Instant,
        override val scheme: ConstantIndex.CredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
        override val userInfo: OidcUserInfoExtended,
        /** Implement to add type metadata field */
        val modifyHeader: JwsHeaderModifierFun = JwsHeaderModifierFun { it },
        val sdAlgorithm: Digest = Digest.SHA256
    ) : CredentialToBeIssued()

    data class Iso(
        val issuerSignedItems: List<IssuerSignedItem>,
        override val expiration: Instant,
        override val scheme: ConstantIndex.CredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
        override val userInfo: OidcUserInfoExtended,
        val revocationKind: RevocationList.Kind
    ) : CredentialToBeIssued()
}

/**
 * Represents a claim that shall be issued to the holder, i.e., serialized into the appropriate credential format.
 *
 * To issue nested structures in SD-JWT, pick one of two options:
 * - Pass a collection of [ClaimToBeIssued] in [value].
 * - Put dots `.` in [name], e.g. `address.region`
 *
 * To issue an array of elements, use a collection of [ClaimToBeIssuedArrayElement] in [value].
 *
 * For each claim, one can select if the claim shall be selectively disclosable or otherwise included plain.
 */
data class ClaimToBeIssued(val name: String, val value: Any, val selectivelyDisclosable: Boolean = true)

/**
 * Represents an element of an array inside an SD-JWT that shall be issued to the holder.
 * Use this in any collection inside [ClaimToBeIssued.value] to correctly serialize the array.
 */
data class ClaimToBeIssuedArrayElement(val value: Any, val selectivelyDisclosable: Boolean = true)
