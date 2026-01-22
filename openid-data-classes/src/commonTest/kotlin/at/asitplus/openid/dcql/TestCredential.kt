package at.asitplus.openid.dcql

/*
 * Software Name : vc-k
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
import kotlinx.serialization.json.JsonElement

sealed interface TestCredential {
    val format: CredentialFormatEnum

    interface JsonCredential : TestCredential {
        val claimStructure: JsonElement
    }

    data class SdJwtCredential(
        override val claimStructure: JsonElement,
        val type: String,
    ) : JsonCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.DC_SD_JWT
    }

    data class MdocCredential(
        val documentType: String,
        val namespaces: Map<String, Map<String, Any>>,
    ) : TestCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.MSO_MDOC
    }

    data class JwtVcCredential(
        override val claimStructure: JsonElement,
        val types: List<String>,
    ) : JsonCredential {
        override val format: CredentialFormatEnum
            get() = CredentialFormatEnum.JWT_VC
    }
}
