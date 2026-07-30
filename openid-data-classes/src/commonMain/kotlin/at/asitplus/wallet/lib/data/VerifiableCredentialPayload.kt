package at.asitplus.wallet.lib.data

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: According to the W3C Verifiable Credential Data Model 1.1 https://www.w3.org/TR/vc-data-model-1.1/#jwt-decoding
 * subject ("sub") can be null if vc.credentialSubject does not have an "id" key.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.JwtClaimNames.IanaRegistered.ClaimNames.RFC7519
import at.asitplus.signum.indispensable.josef.JwtPayload
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Deprecated("Renamed", replaceWith = ReplaceWith("VerifiableCredentialPayload"))
typealias VerifiableCredentialJws = VerifiableCredentialPayload

/**
 * JWS representation of a [VerifiableCredential].
 */
@Serializable
data class VerifiableCredentialPayload(
    @SerialName("vc")
    val vc: VerifiableCredential,
    @SerialName(RFC7519.SUB)
    override val subject: String?,
    @SerialName(RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    override val notBefore: Instant,
    @SerialName(RFC7519.ISS)
    override val issuer: String,
    @SerialName(RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    override val expiration: Instant?,
    @SerialName(RFC7519.JTI)
    override val jwtId: String,
) : JwtPayload {
    override val audience: String? = null
    override val issuedAt: Instant? = null
}