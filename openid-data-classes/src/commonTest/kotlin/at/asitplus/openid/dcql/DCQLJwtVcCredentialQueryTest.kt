package at.asitplus.openid.dcql

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * SPDX-License-Identifier: Apache-2.0
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.data.NonEmptyList.Companion.nonEmptyListOf
import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random

@Suppress("unused")
val DCQLJwtVcCredentialQueryTest by testSuite {
    "serialization" {
        val value = DCQLJwtVcCredentialQuery(
            id = DCQLCredentialQueryIdentifier(
                Random.nextBytes(32).encodeToString(Base64UrlStrict)
            ),
            format = CredentialFormatEnum.JWT_VC,
            claims = DCQLClaimsQueryList(
                DCQLJsonClaimsQuery(
                    path = DCQLClaimsPathPointer(null)
                )
            ),
            meta = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(
                    listOf()
                )
            )
        )

        val expectedJsonObject = buildJsonObject {
            put(DCQLCredentialQuery.SerialNames.ID, JsonPrimitive(value.id.string))
            put(
                DCQLCredentialQuery.SerialNames.FORMAT,
                JsonPrimitive(CredentialFormatEnum.JWT_VC.text)
            )
            put(DCQLCredentialQuery.SerialNames.META,
                buildJsonObject {
                    put(DCQLJwtVcCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES, buildJsonArray {
                        add(buildJsonArray {  })
                    })
                })
            put(DCQLCredentialQuery.SerialNames.CLAIMS, buildJsonArray {
                add(buildJsonObject {
                    put(DCQLJsonClaimsQuery.SerialNames.PATH, buildJsonArray {
                        add(JsonNull)
                    })
                })
            })
        }

        val base: DCQLCredentialQuery = value
        Json.encodeToJsonElement(base) shouldBe expectedJsonObject
        Json.decodeFromJsonElement<DCQLCredentialQuery>(expectedJsonObject) shouldBe value
    }
}