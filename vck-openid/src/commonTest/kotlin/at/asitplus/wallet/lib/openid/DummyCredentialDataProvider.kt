package at.asitplus.wallet.lib.openid

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Credential subject is now a JsonElement
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidScheme
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.LocalDateOrInstant
import at.asitplus.wallet.lib.data.toJsonElement
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.mdl.DrivingPrivilege
import at.asitplus.wallet.mdl.DrivingPrivilegeCode
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import at.asitplus.wallet.mdl.MobileDrivingLicenceScheme
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

object DummyCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
    ): KmmResult<CredentialToBeIssued> = catching {
        val issuance = Clock.System.now()
        val expiration = issuance + defaultLifetime
        if (credentialScheme == ConstantIndex.AtomicAttribute2023) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                ClaimToBeIssued(ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME, "Susanne"),
                ClaimToBeIssued(ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME, "Meier"),
                ClaimToBeIssued(
                    ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH,
                    LocalDate.parse("1990-01-01")
                ),
                ClaimToBeIssued(
                    ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT,
                    Random.Default.nextBytes(32)
                ),
            )
            when (representation) {
                SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = claims,
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                    sdAlgorithm = supportedSdAlgorithms.random()
                )

                PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = AtomicAttribute2023(
                        subjectId,
                        CLAIM_GIVEN_NAME,
                        "Susanne"
                    ).toJsonElement(),
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )

                ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )
            }
        } else if (credentialScheme == MobileDrivingLicenceScheme) {
            val drivingPrivilege = DrivingPrivilege(
                vehicleCategoryCode = "B",
                issueDate = LocalDate.parse("2023-01-01"),
                expiryDate = LocalDate.parse("2033-01-31"),
                codes = arrayOf(DrivingPrivilegeCode(code = "B"))
            )
            var digestId = 0U
            val issuerSignedItems = with(MobileDrivingLicenceDataElements) {
                listOfNotNull(
                    issuerSignedItem(FAMILY_NAME, "Mustermann", digestId++),
                    issuerSignedItem(GIVEN_NAME, "Max", digestId++),
                    issuerSignedItem(BIRTH_DATE, LocalDate.parse("1970-01-01"), digestId++),
                    issuerSignedItem(DOCUMENT_NUMBER, "123456789", digestId++),
                    issuerSignedItem(ISSUE_DATE, LocalDate.parse("2023-01-01"), digestId++),
                    issuerSignedItem(EXPIRY_DATE, LocalDate.parse("2033-01-01"), digestId++),
                    issuerSignedItem(ISSUING_COUNTRY, "AT", digestId++),
                    issuerSignedItem(ISSUING_AUTHORITY, "AT", digestId++),
                    issuerSignedItem(PORTRAIT, Random.Default.nextBytes(32), digestId++),
                    issuerSignedItem(UN_DISTINGUISHING_SIGN, "AT", digestId++),
                    issuerSignedItem(DRIVING_PRIVILEGES, arrayOf(drivingPrivilege), digestId++),
                    issuerSignedItem(AGE_OVER_18, true, digestId++),
                )
            }

            CredentialToBeIssued.Iso(
                issuerSignedItems = issuerSignedItems,
                expiration = expiration,
                scheme = credentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = DummyUserProvider.user,
            )
        } else if (credentialScheme == EuPidScheme) {
            val subjectId = subjectPublicKey.didEncoded
            val familyName = "Musterfrau"
            val givenName = "Maria"
            val birthDate = LocalDate.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val issuanceDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2023-01-01"))
            val expirationDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2027-01-01"))
            val claims = when (representation) {

                SD_JWT -> with(EuPidScheme.SdJwtAttributes) {
                    listOfNotNull(
                        ClaimToBeIssued(FAMILY_NAME, familyName),
                        ClaimToBeIssued(FAMILY_NAME_BIRTH, familyName),
                        ClaimToBeIssued(GIVEN_NAME, givenName),
                        ClaimToBeIssued(GIVEN_NAME_BIRTH, givenName),
                        ClaimToBeIssued(BIRTH_DATE, birthDate),
                        ClaimToBeIssued(AGE_EQUAL_OR_OVER_18, true),
                        ClaimToBeIssued(NATIONALITIES, listOf(nationality)),
                        ClaimToBeIssued(ISSUANCE_DATE, issuanceDate),
                        ClaimToBeIssued(EXPIRY_DATE, expirationDate),
                        ClaimToBeIssued(ISSUING_COUNTRY, issuingCountry),
                        ClaimToBeIssued(ISSUING_AUTHORITY, issuingCountry),
                    )
                }

                ISO_MDOC -> with(EuPidScheme.Attributes) {
                    listOfNotNull(
                        ClaimToBeIssued(FAMILY_NAME, familyName),
                        ClaimToBeIssued(FAMILY_NAME_BIRTH, familyName),
                        ClaimToBeIssued(GIVEN_NAME, givenName),
                        ClaimToBeIssued(GIVEN_NAME_BIRTH, givenName),
                        ClaimToBeIssued(BIRTH_DATE, birthDate),
                        ClaimToBeIssued(AGE_OVER_18, true),
                        ClaimToBeIssued(NATIONALITY, nationality),
                        ClaimToBeIssued(ISSUANCE_DATE, issuanceDate),
                        ClaimToBeIssued(EXPIRY_DATE, expirationDate),
                        ClaimToBeIssued(ISSUING_COUNTRY, issuingCountry),
                        ClaimToBeIssued(ISSUING_AUTHORITY, issuingCountry),
                    )
                }

                else -> null
            }
            when (representation) {
                SD_JWT ->
                    CredentialToBeIssued.VcSd(
                        claims = claims!!,
                        expiration = expiration,
                        scheme = credentialScheme,
                        subjectPublicKey = subjectPublicKey,
                        userInfo = DummyUserProvider.user,
                        sdAlgorithm = supportedSdAlgorithms.random()
                    )

                PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = Json.encodeToJsonElement(
                        EuPidCredential.serializer(), EuPidCredential(
                            id = subjectId,
                            familyName = familyName,
                            givenName = givenName,
                            birthDate = birthDate,
                            ageOver18 = true,
                            issuanceDate = issuanceDate,
                            expiryDate = expirationDate,
                            issuingCountry = issuingCountry,
                            issuingAuthority = issuingCountry,
                        )
                    ),
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )

                ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims!!.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                    scheme = credentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )
            }
        } else {
            throw NotImplementedError()
        }
    }

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.Default.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}
