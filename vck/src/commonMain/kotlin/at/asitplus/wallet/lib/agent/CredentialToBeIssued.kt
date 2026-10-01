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
import at.asitplus.openid.OpenId4VciClaimsPathPointer
import at.asitplus.openid.OpenId4VciClaimsPathPointerSegmentString
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.jws.JwsHeaderModifierFun
import kotlinx.serialization.json.JsonElement
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic
import kotlin.time.Instant

sealed class CredentialToBeIssued {
    abstract val expiration: Instant
    abstract val scheme: CredentialScheme
    abstract val subjectPublicKey: CryptoPublicKey
    abstract val userInfo: OidcUserInfoExtended

    data class VcJwt(
        val subject: JsonElement,
        override val expiration: Instant,
        override val scheme: VcJwtCredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
        override val userInfo: OidcUserInfoExtended,
    ) : CredentialToBeIssued()

    data class VcSd @JvmOverloads constructor(
        val claims: Collection<ClaimToBeIssued>,
        override val expiration: Instant,
        override val scheme: SdJwtCredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
        override val userInfo: OidcUserInfoExtended,
        /** Implement to add type metadata field */
        val modifyHeader: JwsHeaderModifierFun = JwsHeaderModifierFun { it },
        val sdAlgorithm: Digest = Digest.SHA256
    ) : CredentialToBeIssued()

    data class Iso @JvmOverloads constructor(
        val issuerSignedItems: List<IssuerSignedItem>,
        override val expiration: Instant,
        override val scheme: IsoMdocCredentialScheme,
        override val subjectPublicKey: CryptoPublicKey,
        override val userInfo: OidcUserInfoExtended,
        val revocationKind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
        val digest: Digest = Digest.SHA256
    ) : CredentialToBeIssued()
}

/**
 * Represents a claim that shall be issued to the holder, i.e., serialized into the appropriate credential format.
 *
 * To issue nested structures in SD-JWT, pass a collection of [ClaimToBeIssued] in [value], or create one from an
 * [OpenId4VciClaimsPathPointer], e.g. `ClaimToBeIssued(OpenId4VciClaimsPathPointer("address", "region"), "Vienna")`.
 *
 * To issue an array of elements, use a collection of [ClaimToBeIssuedArrayElement] in [value].
 *
 * For each claim, one can select if the claim shall be selectively disclosable or otherwise included plain.
 */
data class ClaimToBeIssued @JvmOverloads constructor(
    val name: String,
    val value: Any,
    val selectivelyDisclosable: Boolean = true,
) {
    companion object {
        /**
         * Creates nested claims from [path]. Only string segments are supported; [selectivelyDisclosable] applies to
         * every generated level.
         */
        operator fun invoke(
            path: OpenId4VciClaimsPathPointer,
            value: Any,
            selectivelyDisclosable: Boolean = true,
        ): ClaimToBeIssued = fromPath(
            path = path.map {
                require(it is OpenId4VciClaimsPathPointerSegmentString) {
                    "ClaimToBeIssued paths must contain only string segments"
                }
                it.string
            },
            value = value,
            selectivelyDisclosable = selectivelyDisclosable,
        )

        /** Java-safe variant of [invoke] using string path segments. */
        @JvmStatic
        @JvmOverloads
        fun fromPath(
            path: List<String>,
            value: Any,
            selectivelyDisclosable: Boolean = true,
        ): ClaimToBeIssued {
            require(path.isNotEmpty()) { "ClaimToBeIssued path must not be empty" }
            return path.dropLast(1)
                .foldRight(ClaimToBeIssued(path.last(), value, selectivelyDisclosable)) { name, nested ->
                    ClaimToBeIssued(name, listOf(nested), selectivelyDisclosable)
                }
        }
    }
}

/**
 * Represents an element of an array inside an SD-JWT that shall be issued to the holder.
 * Use this in any collection inside [ClaimToBeIssued.value] to correctly serialize the array.
 */
data class ClaimToBeIssuedArrayElement @JvmOverloads constructor(
    val value: Any,
    val selectivelyDisclosable: Boolean = true,
)
