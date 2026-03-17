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
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

@Suppress("unused")
val DCQLJwtVcCredentialMetadataAndValidityConstraintsTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLJwtVcCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES shouldBe "type_values"
        }
    }
    "instance serialization" {
        val serialized = Json.encodeToJsonElement(
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(listOf("dummy document type"))
            )
        ).jsonObject
        DCQLJwtVcCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES shouldBeIn serialized.keys
    }
    "handle null or empty " {
        shouldThrow<IllegalArgumentException> {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(emptyList()),
            ).validate(emptyList()).getOrThrow()
        }
        shouldThrow<IllegalArgumentException> {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(listOf("dummy document type")),
            ).validate(null).getOrThrow()
        }
    }
    "constraints query" {
        shouldNotThrowAny {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(listOf("dummy document type")),
            ).validate(listOf("dummy document type")).getOrThrow()

            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(listOf("dummy document type")),
            ).validateCredentialConformance(
                DCQLVcJwsCredential(
                    claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {  }),
                    types = listOf("dummy document type"),
                    satisfiesCryptographicHolderBinding = false,
                    authorityKeyIdentifiers = listOf()
                )
            ).getOrThrow()
        }
        shouldThrowAny {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(listOf("dummy document type")),
            ).validate(listOf("DIFFERENT dummy document type")).getOrThrow()
        }
        shouldThrowAny {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = nonEmptyListOf(listOf("dummy document type")),
            ).validateCredentialConformance(
                DCQLVcJwsCredential(
                    claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(buildJsonObject {  }),
                    types = listOf("DIFFERENT dummy document type"),
                    satisfiesCryptographicHolderBinding = false,
                    authorityKeyIdentifiers = listOf()
                )
            ).getOrThrow()
        }
    }
}