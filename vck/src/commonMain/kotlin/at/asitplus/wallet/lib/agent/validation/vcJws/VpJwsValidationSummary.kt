package at.asitplus.wallet.lib.agent.validation.vcJws

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
* Modifications: According to the W3C Verifiable Credential Data Model 1.1 https://www.w3.org/TR/vc-data-model-1.1/#jwt-encoding,
 * "iss MUST represent the issuer property of a verifiable credential or the holder property of a verifiable presentation."
 * So in this case the issuer should be the wallet holder, represented by it's DID.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.signum.indispensable.CryptoPublicKey

data class VpJwsValidationSummary(
    val inconsistentIssuerError: InconsistentIssuerError?,
) {
    val isSuccess = listOf(
        inconsistentIssuerError == null,
    ).all { it }

    data class InconsistentIssuerError(
        val vpPublicKey: CryptoPublicKey?,
        val vpIssuer: String,
    )
}