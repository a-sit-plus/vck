package at.asitplus.wallet.lib.agent.validation.vcJws

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: According to the W3C Verifiable Credential Data Model 1.1  subject ("sub") can be null
 * if vc.credentialSubject does not have "id" key.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun

data class VcJwsInputValidator(
    val vcJwsContentSemanticsValidator: VcJwsContentSemanticsValidator = VcJwsContentSemanticsValidator(),
    val vpJwsValidator: VpJwsValidator = VpJwsValidator(),
    val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
) {
    suspend operator fun invoke(
        input: String,
        publicKey: CryptoPublicKey?,
        vpJws: JwsSigned<VerifiablePresentationJws>?,
    ): VcJwsInputValidationResult {
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
            return VcJwsInputValidationResult.ParsingError(input, it)
        }
        val vcJws = jws.payload

        return VcJwsInputValidationResult.ContentValidationSummary(
            input = input,
            parsed = jws,
            isIntegrityGood = verifyJwsObject(jws).isSuccess,
            subjectMatchingResult =
                vcJws.subject?.let { subject ->
                    publicKey?.let {
                        SubjectMatchingResult(
                            subject = subject,
                            publicKey = publicKey,
                            isSuccess = it.matchesIdentifier(subject)
                        )
                    }
                },
            contentSemanticsValidationSummary = vcJwsContentSemanticsValidator.invoke(vcJws),
            vpValidationSummary = vpJws?.let { vpJwsValidator.invoke(publicKey, vpJws) }
        )
    }
}

