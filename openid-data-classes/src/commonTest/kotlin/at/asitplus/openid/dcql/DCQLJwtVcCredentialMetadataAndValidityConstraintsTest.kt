package at.asitplus.openid.dcql

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * SPDX-License-Identifier: Apache-2.0
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.openid.CredentialFormatEnum
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

val DCQLJwtVcCredentialMetadataAndValidityConstraintsTest by testSuite {
    "specification" - {
        "serial names" {
            DCQLJwtVcCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES shouldBe "type_values"
        }
    }
    "instance serialization" {
        val serialized = Json.encodeToJsonElement(
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = listOf(listOf("dummy document type"))
            )
        ).jsonObject
        DCQLJwtVcCredentialMetadataAndValidityConstraints.SerialNames.TYPE_VALUES shouldBeIn serialized.keys
    }
    "handle null or empty " {
        shouldThrow<IllegalArgumentException> {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = listOf(emptyList()),
            ).validate(emptyList()).getOrThrow()
        }
        shouldThrow<IllegalArgumentException> {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = listOf(listOf("dummy document type")),
            ).validate(null).getOrThrow()
        }
    }
    "constraints query" {
        shouldNotThrowAny {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = listOf(listOf("dummy document type")),
            ).validate(listOf("dummy document type")).getOrThrow()

            DCQLCredentialQuery.Procedures.validateCredentialMetadataAndValidityConstraints(
                credential = "",
                credentialFormatIdentifier = CredentialFormatEnum.JWT_VC,
                credentialMetadataAndValidityConstraints = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                    typeValues = listOf(listOf("dummy document type")),
                ),
                mdocCredentialDoctypeExtractor = {
                    throw IllegalArgumentException("MDOC credential type cannot be extracted")
                },
                sdJwtCredentialTypeExtractor = {
                    throw IllegalArgumentException("JWT-VC credential type cannot be extracted")
                },
                jwtVcCredentialTypeExtractor = { listOf("dummy document type") }
            ).getOrThrow()
        }
        shouldThrowAny {
            DCQLJwtVcCredentialMetadataAndValidityConstraints(
                typeValues = listOf(listOf("dummy document type")),
            ).validate(listOf("DIFFERENT dummy document type")).getOrThrow()
        }
        shouldThrowAny {
            DCQLCredentialQuery.Procedures.validateCredentialMetadataAndValidityConstraints(
                credential = "",
                credentialFormatIdentifier = CredentialFormatEnum.JWT_VC,
                credentialMetadataAndValidityConstraints = DCQLJwtVcCredentialMetadataAndValidityConstraints(
                    typeValues = listOf(listOf("dummy document type")),
                ),
                mdocCredentialDoctypeExtractor = {
                    throw IllegalArgumentException("MDOC credential type cannot be extracted")
                },
                sdJwtCredentialTypeExtractor = {
                    throw IllegalArgumentException("SD-JWT credential type cannot be extracted")
                },
                jwtVcCredentialTypeExtractor = { listOf("DIFFERENT dummy document type") }
            ).getOrThrow()
        }
    }
}