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
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

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
            claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(
                namespaces.mapValues { (_, elements) -> elements.mapValues { (_, value) -> value.toTestJsonValue() } }
            )
        )
    }

    fun isSatisfiable(availableCredentials: List<TestCredential>): Boolean {
        val matching = execute(availableCredentials)
        return dcqlQuery.checkCredentialSetQueryRequirements(
            matching.credentialQueryMatches.filter {
                it.value.isNotEmpty()
            }.keys
        ).isSuccess
    }
}

/** The JSON value of a test data element, as the wallet converts it from CBOR (OpenID4VP 1.0, 6.3). */
private fun Any.toTestJsonValue(): JsonElement = when (this) {
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Number -> JsonPrimitive(this)
    else -> JsonNull
}
