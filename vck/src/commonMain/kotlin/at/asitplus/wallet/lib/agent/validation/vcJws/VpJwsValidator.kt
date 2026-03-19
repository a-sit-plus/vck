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
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import io.github.aakira.napier.Napier

class VpJwsValidator {
    operator fun invoke(
        publicKey: CryptoPublicKey?,
        vpJws: JwsCompact,
    ) = vpJws.getPayload<VerifiablePresentationJws>().getOrThrow().let {
        VpJwsValidationSummary(
            inconsistentIssuerError =
                if (!(publicKey?.matchesIdentifier(it.issuer) ?: false)) {
                    VpJwsValidationSummary.InconsistentIssuerError(
                        vpPublicKey = publicKey,
                        vpIssuer = it.issuer
                    )
                } else null
        ).also {
            if (it.isSuccess) {
                Napier.d("VP mapping is valid")
            }
        }
    }
}

