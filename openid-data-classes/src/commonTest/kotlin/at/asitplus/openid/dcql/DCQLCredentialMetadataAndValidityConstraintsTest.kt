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

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val DCQLCredentialMetadataAndValidityConstraintsTest by testSuite {
     "serialization" - {
         "iso" {
             val value = DCQLIsoMdocCredentialMetadataAndValidityConstraints(
                 doctypeValue = "test"
             )

             val base: DCQLCredentialMetadataAndValidityConstraints = value
             val serialized = Json.encodeToJsonElement(base)
             serialized shouldBe Json.encodeToJsonElement(value)
             serialized.jsonObject.entries shouldHaveSize 1

             DCQLIsoMdocCredentialMetadataAndValidityConstraints.SerialNames.DOCTYPE_VALUE shouldBeIn serialized.jsonObject.keys
         }
         "sd-jwt" {
             val value = DCQLSdJwtCredentialMetadataAndValidityConstraints(
                 vctValues = listOf("test")
             )

             val base: DCQLCredentialMetadataAndValidityConstraints = value
             val serialized = Json.encodeToJsonElement(base)
             serialized shouldBe Json.encodeToJsonElement(value)
             serialized.jsonObject.entries shouldHaveSize 1

             DCQLSdJwtCredentialMetadataAndValidityConstraints.SerialNames.VCT_VALUES shouldBeIn serialized.jsonObject.keys
         }
         "jwt-vc" {
             val value = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                 typeValues = listOf(listOf("test"))
             )

             val base: DCQLCredentialMetadataAndValidityConstraints = value
             val serialized = Json.encodeToJsonElement(base)
             serialized shouldBe Json.encodeToJsonElement(value)
             serialized.jsonObject.entries shouldHaveSize 1

             DCQLJwtVcCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES shouldBeIn serialized.jsonObject.keys
         }
     }
}