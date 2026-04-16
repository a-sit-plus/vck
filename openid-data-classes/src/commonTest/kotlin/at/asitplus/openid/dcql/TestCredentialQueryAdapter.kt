package at.asitplus.openid.dcql

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Added jwt_vc_json DCQL support for Orange implementation
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import kotlin.jvm.JvmInline

@JvmInline
value class TestCredentialQueryAdapter(val dcqlQuery: DCQLQuery) {
    fun execute(availableCredentials: List<TestCredential>) = dcqlQuery.findCredentialQueryMatches(
        availableCredentials = availableCredentials.map {
            it.toDCQLCredential()
        }
    )

    private fun TestCredential.toDCQLCredential() = when(this) {
        is TestCredential.SdJwtCredential -> DCQLSdJwtCredential(
            type = type,
            satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding,
            authorityKeyIdentifiers = authorityKeyIdentifiers,
            claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(claimStructure)
        )

        is TestCredential.JwtVcCredential -> DCQLVcJwsCredential(
            types = types,
            satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding,
            authorityKeyIdentifiers = authorityKeyIdentifiers,
            claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(claimStructure)
        )

        is TestCredential.MdocCredential -> DCQLIsoMdocCredential(
            documentType = documentType,
            satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding,
            authorityKeyIdentifiers = authorityKeyIdentifiers,
            claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(namespaces)
        )
    }

    fun isSatisfiable(availableCredentials: List<TestCredential>): Boolean {
        val matching = execute(availableCredentials)
        return dcqlQuery.isCredentialSetQueriesSatisfiedWith(
            matching.credentialQueryMatches.filter {
                it.value.isNotEmpty()
            }.keys
        )
    }
}
