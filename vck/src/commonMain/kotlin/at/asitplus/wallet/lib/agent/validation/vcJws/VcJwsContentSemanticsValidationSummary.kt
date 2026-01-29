package at.asitplus.wallet.lib.agent.validation.vcJws

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

import kotlin.time.Instant

data class VcJwsContentSemanticsValidationSummary(
    val inconsistentIssuerError: InconsistentIssuerError?,
    val inconsistentIdentifierError: InconsistentIdentifierError?,
    val inconsistentSubjectError: InconsistentSubjectError?,
    val missingCredentialTypeError: MissingCredentialTypeError?,
    val inconsistentNotBeforeTimeError: InconsistentNotBeforeTimeError?,
    val inconsistentExpirationTimeError: InconsistentExpirationTimeError?,
) {
    val isSuccess = listOf(
        inconsistentIssuerError == null,
        inconsistentIdentifierError == null,
        inconsistentSubjectError == null,
        missingCredentialTypeError == null,
        inconsistentNotBeforeTimeError == null,
        inconsistentExpirationTimeError == null,
    ).all { it }

    data class InconsistentIssuerError(
        val jwsIssuer: String,
        val credentialIssuer: String,
    )

    data class InconsistentIdentifierError(
        val jwsId: String,
        val credentialId: String,
    )

    data class InconsistentSubjectError(
        val jwsSubject: String?,
        val credentialSubjectId: String?,
    )

    data class MissingCredentialTypeError(
        val missingType: String,
        val availableTypes: Collection<String>,
    )

    data class InconsistentNotBeforeTimeError(
        val jwsNotBefore: Instant,
        val credentialIssuanceDate: Instant,
    )

    data class InconsistentExpirationTimeError(
        val jwsExpirationTime: Instant?,
        val credentialExpirationDate: Instant?,
    )
}