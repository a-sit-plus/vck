package at.asitplus.wallet.lib.agent.validation.vcJws

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Rename VcJwsToVpJwsMappingValidationSummary to VpJwsValidationSummary
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.VerifiableCredentialJws

sealed interface VcJwsInputValidationResult {
    val isSuccess: Boolean

    data class ParsingError(
        val input: String,
        val throwable: Throwable,
    ) : VcJwsInputValidationResult {
        override val isSuccess: Boolean
            get() = false
    }

    data class ContentValidationSummary(
        val input: String,
        val parsed: JwsSigned<VerifiableCredentialJws>,
        val isIntegrityGood: Boolean,
        val subjectMatchingResult: SubjectMatchingResult?,
        val contentSemanticsValidationSummary: VcJwsContentSemanticsValidationSummary,
        val vpValidationSummary: VpJwsValidationSummary?,
    ) : VcJwsInputValidationResult {
        val payload: VerifiableCredentialJws
            get() = parsed.payload

        override val isSuccess: Boolean
            get() = listOf(
                isIntegrityGood,
                subjectMatchingResult?.isSuccess != false,
                contentSemanticsValidationSummary.isSuccess,
                vpValidationSummary?.isSuccess != false,
            ).all { it }
    }
}