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
import at.asitplus.wallet.eupid.EU_PID_DOCTYPE
import at.asitplus.wallet.eupid.EuPidCredential
import at.asitplus.wallet.eupid.EuPidDataElements
import at.asitplus.wallet.eupidsdjwt.EU_PID_SD_JWT_VCT
import at.asitplus.wallet.eupidsdjwt.EuPidSdJwtDataElements
import at.asitplus.wallet.lib.agent.ClaimToBeIssued
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.EphemeralKeyWithSelfSignedCert
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.toStoreCredentialInput
import at.asitplus.wallet.lib.data.AtomicAttribute2023
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_DATE_OF_BIRTH
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_FAMILY_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_GIVEN_NAME
import at.asitplus.wallet.lib.data.ConstantIndex.AtomicAttribute2023.CLAIM_PORTRAIT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.LocalDateOrInstant
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc3986.toUri
import at.asitplus.wallet.lib.data.toJsonElement
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import at.asitplus.wallet.mdl.DrivingPrivilege
import at.asitplus.wallet.mdl.DrivingPrivilegeCode
import at.asitplus.wallet.mdl.MDL_DOCTYPE
import at.asitplus.wallet.mdl.MobileDrivingLicenceDataElements
import kotlinx.datetime.LocalDate
import kotlinx.serialization.json.Json
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

object DummyCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    suspend fun issueAndStoreSdJwt(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issueSdJwt(
            IssuerAgent(
                keyMaterial = EphemeralKeyWithoutCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ),
            holderKeyMaterial,
            credentialScheme
        ).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueAndStoreSdJwt(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        issuer: Issuer
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issueSdJwt(issuer, holderKeyMaterial).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueSdJwt(
        issuer: Issuer,
        holderKeyMaterial: KeyMaterial,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): Issuer.IssuedCredential = issuer.issueCredential(
        getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            SD_JWT,
        ).getOrThrow()
    ).getOrThrow()

    suspend fun issueAndStoreIsoMdoc(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issueIsoMdoc(
            IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ),
            holderKeyMaterial,
            credentialScheme
        ).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueAndStoreIsoMdoc(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        issuer: Issuer,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issueIsoMdoc(issuer, holderKeyMaterial, credentialScheme).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueIsoMdoc(
        issuer: Issuer,
        holderKeyMaterial: KeyMaterial,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): Issuer.IssuedCredential = issuer.issueCredential(
        getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            ISO_MDOC,
        ).getOrThrow()
    ).getOrThrow()

    suspend fun issueAndStorePlainJwt(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issuePlainJwt(
            IssuerAgent(
                keyMaterial = EphemeralKeyWithSelfSignedCert(),
                identifier = "https://issuer.example.com/".toUri(),
                randomSource = RandomSource.Default
            ),
            holderKeyMaterial,
            credentialScheme
        ).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueAndStorePlainJwt(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        issuer: Issuer
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issuePlainJwt(issuer, holderKeyMaterial).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issuePlainJwt(
        issuer: Issuer,
        holderKeyMaterial: KeyMaterial,
        credentialScheme: CredentialScheme = ConstantIndex.AtomicAttribute2023,
    ): Issuer.IssuedCredential = issuer.issueCredential(
        getCredential(
            holderKeyMaterial.publicKey,
            credentialScheme,
            PLAIN_JWT,
        ).getOrThrow()
    ).getOrThrow()

    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: CredentialRepresentation,
    ): KmmResult<CredentialToBeIssued> = catching {
        val issuance = Clock.System.now()
        val expiration = issuance + defaultLifetime
        if (credentialScheme == ConstantIndex.AtomicAttribute2023) {
            val subjectId = subjectPublicKey.didEncoded
            val claims = listOfNotNull(
                ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
                ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
                ClaimToBeIssued(CLAIM_DATE_OF_BIRTH, LocalDate.parse("1990-01-01")),
                ClaimToBeIssued(CLAIM_PORTRAIT, Random.nextBytes(32)),
            )
            when (representation) {
                SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = claims,
                    expiration = expiration,
                    scheme = credentialScheme as SdJwtCredentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                    sdAlgorithm = supportedSdAlgorithms.random()
                )

                PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = AtomicAttribute2023(subjectId, CLAIM_GIVEN_NAME, "Susanne").toJsonElement(),
                    expiration = expiration,
                    scheme = credentialScheme as VcJwtCredentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )

                ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = claims.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                    scheme = credentialScheme as IsoMdocCredentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )
            }
        } else if (credentialScheme.isoDocType == MDL_DOCTYPE) {
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
                    issuerSignedItem(PORTRAIT, Random.nextBytes(32), digestId++),
                    issuerSignedItem(UN_DISTINGUISHING_SIGN, "AT", digestId++),
                    issuerSignedItem(DRIVING_PRIVILEGES, arrayOf(drivingPrivilege), digestId++),
                    issuerSignedItem(AGE_OVER_18, true, digestId++),
                )
            }

            CredentialToBeIssued.Iso(
                issuerSignedItems = issuerSignedItems,
                expiration = expiration,
                scheme = credentialScheme as IsoMdocCredentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = DummyUserProvider.user,
            )
        } else if (credentialScheme.isoDocType == EU_PID_DOCTYPE || credentialScheme.vcType == "EuPid2023") {
            val subjectId = subjectPublicKey.didEncoded
            val familyName = "Musterfrau"
            val givenName = "Maria"
            val birthDate = LocalDate.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val issuanceDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2023-01-01"))
            val expirationDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2027-01-01"))
            when (representation) {
                PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                    subject = Json.encodeToJsonElement(
                        EuPidCredential.serializer(), EuPidCredential(
                            id = subjectId,
                            familyName = familyName,
                            givenName = givenName,
                            birthDate = birthDate,
                            issuanceDate = issuanceDate,
                            expiryDate = expirationDate,
                            issuingCountry = issuingCountry,
                            issuingAuthority = issuingCountry,
                        )
                    ),
                    expiration = expiration,
                    scheme = credentialScheme as VcJwtCredentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )

                ISO_MDOC -> CredentialToBeIssued.Iso(
                    issuerSignedItems = with(EuPidDataElements) {
                        listOfNotNull(
                            ClaimToBeIssued(FAMILY_NAME, familyName),
                            ClaimToBeIssued(FAMILY_NAME_BIRTH, familyName),
                            ClaimToBeIssued(GIVEN_NAME, givenName),
                            ClaimToBeIssued(GIVEN_NAME_BIRTH, givenName),
                            ClaimToBeIssued(BIRTH_DATE, birthDate),
                            ClaimToBeIssued(NATIONALITY, nationality),
                            ClaimToBeIssued(ISSUANCE_DATE, issuanceDate),
                            ClaimToBeIssued(EXPIRY_DATE, expirationDate),
                            ClaimToBeIssued(ISSUING_COUNTRY, issuingCountry),
                            ClaimToBeIssued(ISSUING_AUTHORITY, issuingCountry),
                        )
                    }.mapIndexed { index, claim ->
                        issuerSignedItem(claim.name, claim.value, index.toUInt())
                    },
                    expiration = expiration,
                    scheme = credentialScheme as IsoMdocCredentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                )

                else -> throw NotImplementedError()
            }
        } else if (credentialScheme.sdJwtType == EU_PID_SD_JWT_VCT) {
            val subjectId = subjectPublicKey.didEncoded
            val familyName = "Musterfrau"
            val givenName = "Maria"
            val birthDate = LocalDate.parse("1970-01-01")
            val issuingCountry = "AT"
            val nationality = "FR"
            val issuanceDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2023-01-01"))
            val expirationDate = LocalDateOrInstant.LocalDate(LocalDate.parse("2027-01-01"))
            when (representation) {
                SD_JWT -> CredentialToBeIssued.VcSd(
                    claims = with(EuPidSdJwtDataElements) {
                        listOfNotNull(
                            ClaimToBeIssued(FAMILY_NAME, familyName),
                            ClaimToBeIssued(FAMILY_NAME_BIRTH, familyName),
                            ClaimToBeIssued(GIVEN_NAME, givenName),
                            ClaimToBeIssued(GIVEN_NAME_BIRTH, givenName),
                            ClaimToBeIssued(BIRTH_DATE, birthDate),
                            ClaimToBeIssued(NATIONALITIES, listOf(nationality)),
                            ClaimToBeIssued(ISSUANCE_DATE, issuanceDate),
                            ClaimToBeIssued(EXPIRY_DATE, expirationDate),
                            ClaimToBeIssued(ISSUING_COUNTRY, issuingCountry),
                            ClaimToBeIssued(ISSUING_AUTHORITY, issuingCountry),
                        )
                    },
                    expiration = expiration,
                    scheme = credentialScheme as SdJwtCredentialScheme,
                    subjectPublicKey = subjectPublicKey,
                    userInfo = DummyUserProvider.user,
                    sdAlgorithm = supportedSdAlgorithms.random()
                )

                else -> throw NotImplementedError()
            }
        } else {
            throw NotImplementedError()
        }
    }

    private fun issuerSignedItem(name: String, value: Any, digestId: UInt) =
        IssuerSignedItem(
            digestId = digestId,
            random = Random.nextBytes(16),
            elementIdentifier = name,
            elementValue = value
        )
}
