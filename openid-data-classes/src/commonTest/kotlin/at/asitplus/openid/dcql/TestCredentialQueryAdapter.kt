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
    fun execute(availableCredentials: List<TestCredential>) = dcqlQuery.execute(
        availableCredentials = availableCredentials,
        credentialClaimStructureExtractor = {
            when (it) {
                is TestCredential.JsonCredential -> {
                    DCQLCredentialClaimStructure.JsonBasedStructure(it.claimStructure)
                }

                is TestCredential.MdocCredential -> {
                    DCQLCredentialClaimStructure.IsoMdocStructure(it.namespaces)
                }
            }
        },
        credentialFormatExtractor = {
            it.format
        },
        mdocCredentialDoctypeExtractor = {
            when (it) {
                is TestCredential.JsonCredential -> throw IllegalArgumentException("Json Credentials do not have an MDOC document type.")
                is TestCredential.MdocCredential -> it.documentType
            }
        },
        sdJwtCredentialTypeExtractor = {
            when (it) {
                is TestCredential.SdJwtCredential -> it.type
                else -> throw IllegalArgumentException("Json Credentials do not have an SD-JWT document type.")
            }
        },
        jwtVcCredentialTypeExtractor = {
            when (it) {
                is TestCredential.JwtVcCredential -> it.types
                else -> throw IllegalArgumentException("Json Credentials do not have an JWT-VC document type.")
            }
        },
    )
}
