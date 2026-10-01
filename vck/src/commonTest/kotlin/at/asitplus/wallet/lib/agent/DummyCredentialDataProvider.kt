package at.asitplus.wallet.lib.agent

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
import at.asitplus.openid.OidcUserInfo
import at.asitplus.openid.OidcUserInfoExtended
import at.asitplus.signum.indispensable.CryptoPublicKey
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
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationList
import at.asitplus.wallet.lib.data.toJsonElement
import at.asitplus.wallet.lib.extensions.supportedSdAlgorithms
import io.github.aakira.napier.Napier
import kotlinx.datetime.LocalDate
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

object DummyCredentialDataProvider {

    private val defaultLifetime = 1.minutes

    suspend fun issueAndStoreSdJwt(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        issuer: Issuer
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issueSdJwt(issuer, holderKeyMaterial).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueSdJwt(
        issuer: Issuer,
        holderKeyMaterial: KeyMaterial
    ): Issuer.IssuedCredential = issuer.issueCredential(
        getCredential(
            holderKeyMaterial.publicKey,
            ConstantIndex.AtomicAttribute2023,
            SD_JWT,
        ).getOrThrow()
    ).getOrThrow()

    suspend fun issueAndStoreIsoMdoc(
        holder: Holder,
        holderKeyMaterial: KeyMaterial,
        issuer: Issuer,
        revocationKind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): SubjectCredentialStore.StoreEntry = holder.storeCredential(
        issueIsoMdoc(issuer, holderKeyMaterial, revocationKind).toStoreCredentialInput()
    ).getOrThrow()

    suspend fun issueIsoMdoc(
        issuer: Issuer,
        holderKeyMaterial: KeyMaterial,
        revocationKind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): Issuer.IssuedCredential = issuer.issueCredential(
        getCredential(
            holderKeyMaterial.publicKey,
            ConstantIndex.AtomicAttribute2023,
            ISO_MDOC,
            revocationKind
        ).getOrThrow()
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
        holderKeyMaterial: KeyMaterial
    ): Issuer.IssuedCredential = issuer.issueCredential(
        getCredential(
            holderKeyMaterial.publicKey,
            ConstantIndex.AtomicAttribute2023,
            PLAIN_JWT,
        ).getOrThrow()
    ).getOrThrow()

    fun getCredential(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: CredentialRepresentation,
        revocationKind: RevocationList.Kind = RevocationList.Kind.STATUS_LIST,
    ): KmmResult<CredentialToBeIssued> = catching {
        if (representation != ISO_MDOC && revocationKind != RevocationList.Kind.STATUS_LIST) {
            Napier.w { "Revocation via IdentifierList only defined for ISO - Input ignored!" }
        }
        val expiration = Clock.System.now() + defaultLifetime
        val claims = listOf(
            ClaimToBeIssued(CLAIM_GIVEN_NAME, "Susanne"),
            ClaimToBeIssued(CLAIM_FAMILY_NAME, "Meier"),
            ClaimToBeIssued(CLAIM_DATE_OF_BIRTH, LocalDate.parse("1990-01-01")),
            ClaimToBeIssued(CLAIM_PORTRAIT, Random.nextBytes(32)),
        )
        val subjectId = subjectPublicKey.didEncoded
        when (representation) {
            SD_JWT -> CredentialToBeIssued.VcSd(
                claims = claims,
                expiration = expiration,
                scheme = credentialScheme as SdJwtCredentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                sdAlgorithm = supportedSdAlgorithms.random()
            )

            PLAIN_JWT -> CredentialToBeIssued.VcJwt(
                subject = AtomicAttribute2023(subjectId, CLAIM_GIVEN_NAME, "Susanne").toJsonElement(),
                expiration = expiration,
                scheme = credentialScheme as VcJwtCredentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
            )

            ISO_MDOC -> CredentialToBeIssued.Iso(
                issuerSignedItems = claims.mapIndexed { index, claim ->
                    issuerSignedItem(claim.name, claim.value, index.toUInt())
                },
                expiration = expiration,
                scheme = credentialScheme as IsoMdocCredentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                revocationKind = revocationKind,
            )
        }
    }

    fun getCredentialForClaim(
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: CredentialRepresentation,
        claim: ClaimToBeIssued
    ): KmmResult<CredentialToBeIssued> = catching {
        val expiration = Clock.System.now() + defaultLifetime
        when (representation) {
            SD_JWT -> CredentialToBeIssued.VcSd(
                claims = listOf(claim),
                expiration = expiration,
                scheme = credentialScheme as SdJwtCredentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
                sdAlgorithm = supportedSdAlgorithms.random()
            )

            PLAIN_JWT -> throw IllegalArgumentException("PLAIN_JWT")

            ISO_MDOC -> CredentialToBeIssued.Iso(
                issuerSignedItems = listOf(issuerSignedItem(claim.name, claim.value, 0U)),
                expiration = expiration,
                scheme = credentialScheme as IsoMdocCredentialScheme,
                subjectPublicKey = subjectPublicKey,
                userInfo = OidcUserInfoExtended.fromOidcUserInfo(OidcUserInfo("subject")).getOrThrow(),
            )
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