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
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Suppress("unused")
val DCQLIsoMdocCredentialMetadataAndValidityConstraintsTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE shouldBe "doctype_value"
        }
    }
    "instance serialization" {
        val serialized = Json.encodeToJsonElement(
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            )
        ).jsonObject
        DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE shouldBeIn serialized.keys
    }
    "constraints query" {
        shouldNotThrowAny {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            ).validate("dummy document type").getOrThrow()

            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            ).validateCredentialConformance(
                DCQLIsoMdocCredential(
                    claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(mapOf()),
                    documentType = "dummy document type",
                    satisfiesCryptographicHolderBinding = true,
                    authorityKeyIdentifiers = listOf()
                )
            ).getOrThrow()
        }
        shouldThrowAny {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            ).validate("DIFFERENT dummy document type").getOrThrow()
        }
        shouldThrowAny {
            DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                doctypeValue = "dummy document type"
            ).validateCredentialConformance(
                DCQLIsoMdocCredential(
                    claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(mapOf()),
                    documentType = "DIFFERENT dummy document type",
                    satisfiesCryptographicHolderBinding = true,
                    authorityKeyIdentifiers = listOf()
                )
            ).getOrThrow()
        }
    }
}