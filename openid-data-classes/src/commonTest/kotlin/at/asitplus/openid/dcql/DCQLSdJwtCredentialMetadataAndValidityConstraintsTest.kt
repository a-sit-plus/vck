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

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Suppress("unused")
val DCQLSdJwtCredentialMetadataAndValidityConstraintsTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES shouldBe "vct_values"
        }
    }
    "instance serialization" {
        val serialized = Json.encodeToJsonElement(
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type")
            )
        ).jsonObject
        DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES shouldBeIn serialized.keys
    }
    "constraints query" {
        shouldNotThrowAny {
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type"),
            ).validate("dummy document type").getOrThrow()

            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type"),
            ).validateCredentialConformance(
                DCQLSdJwtCredential(
                    claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {  }),
                    type = "dummy document type",
                    satisfiesCryptographicHolderBinding = false,
                    authorityKeyIdentifiers = listOf()
                )
            ).getOrThrow()
        }
        shouldThrowAny {
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type"),
            ).validate("DIFFERENT dummy document type").getOrThrow()
        }
        shouldThrowAny {
            DCQLSdJwtCredentialMetadataAndValidityConstraints(
                vctValues = listOf("dummy document type"),
            ).validateCredentialConformance(
                DCQLSdJwtCredential(
                    claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {  }),
                    type = "DIFFERENT dummy document type",
                    satisfiesCryptographicHolderBinding = false,
                    authorityKeyIdentifiers = listOf()
                )
            ).getOrThrow()
        }
    }
}