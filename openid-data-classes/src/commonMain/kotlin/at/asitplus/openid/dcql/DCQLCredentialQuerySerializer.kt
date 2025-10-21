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

import at.asitplus.openid.CredentialFormatEnum
import kotlinx.serialization.DeserializationStrategy
import kotlinx.serialization.json.JsonContentPolymorphicSerializer
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

object DCQLCredentialQuerySerializer : JsonContentPolymorphicSerializer<DCQLCredentialQuery>(DCQLCredentialQuery::class) {
    override fun selectDeserializer(element: JsonElement): DeserializationStrategy<DCQLCredentialQuery> {
        val parameters = element.jsonObject
        val credentialFormatIdentifier =
            parameters[DCQLCredentialQuery.SerialNames.FORMAT]?.jsonPrimitive?.content?.let {
                CredentialFormatEnum.parse(it)
            }
        return when (credentialFormatIdentifier) {
            CredentialFormatEnum.MSO_MDOC -> DCQLIsoMdocCredentialQuery.serializer()
            CredentialFormatEnum.DC_SD_JWT -> DCQLSdJwtCredentialQuery.serializer()
            CredentialFormatEnum.JWT_VC -> DCQLJwtVcCredentialQuery.serializer()
            CredentialFormatEnum.JWT_VC -> DCQLW3CVerifiableCredentialQuery.serializer()
            else -> throw IllegalArgumentException("Credential format not supported: ${credentialFormatIdentifier}")
        }
    }
}