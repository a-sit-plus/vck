package at.asitplus.wallet.lib.procedures.dcql

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

import at.asitplus.KmmResult
import at.asitplus.openid.dcql.DCQLAuthorityKeyIdentifier
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryResult
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlin.jvm.JvmInline

@JvmInline
value class DCQLQueryAdapter(val dcqlQuery: DCQLQuery) {
    fun select(
        credentials: List<SubjectCredentialStore.StoreEntry>
    ): KmmResult<DCQLQueryResult<SubjectCredentialStore.StoreEntry>> = dcqlQuery.execute(
        availableCredentials = credentials,
        credentialFormatExtractor = { it.credentialFormat },
        mdocCredentialDoctypeExtractor = {
            if (it !is SubjectCredentialStore.StoreEntry.Iso) {
                throw IllegalArgumentException("Value is not an MDOC credential")
            }
            it.scheme!!.isoDocType!!
        },
        sdJwtCredentialTypeExtractor = {
            if (it !is SubjectCredentialStore.StoreEntry.SdJwt) {
                throw IllegalArgumentException("Value is not an SD-JWT credential")
            }
            it.scheme!!.sdJwtType!!
        },
        jwtVcCredentialTypeExtractor = {
            if (it !is SubjectCredentialStore.StoreEntry.Vc) {
                throw IllegalArgumentException("Value is not an JWT-VC credential")
            }
            it.vc.vc.type.toList()
        },
        credentialClaimStructureExtractor = { storeEntry ->
            when (storeEntry) {
                is SubjectCredentialStore.StoreEntry.Iso -> DCQLCredentialClaimStructure.IsoMdocStructure(
                    storeEntry.issuerSigned.namespaces?.mapValues { entry ->
                        entry.value.entries.associate {
                            it.value.elementIdentifier to it.value.elementValue
                        }
                    } ?: mapOf()
                )

                else -> DCQLCredentialClaimStructure.JsonBasedStructure(
                    CredentialToJsonConverter.toJsonElement(storeEntry)
                )
            }
        },
        satisfiesCryptographicHolderBinding = {
            when (it) {
                is SubjectCredentialStore.StoreEntry.Iso -> it.issuerSigned.issuerAuth.payload?.deviceKeyInfo != null
                is SubjectCredentialStore.StoreEntry.SdJwt -> it.sdJwt.confirmationClaim != null
                is SubjectCredentialStore.StoreEntry.Vc -> it.vc.subject.isNotEmpty()
            }
        },
        authorityKeyIdentifiers = {
            when (it) {
                is SubjectCredentialStore.StoreEntry.Iso -> it.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.flatMap {
                    X509Certificate.decodeFromByteArray(it)?.toAuthorityKeyIdentifiers() ?: listOf()
                } ?: listOf()

                is SubjectCredentialStore.StoreEntry.SdJwt -> SdJwtSigned.parseCatching(
                    it.vcSerialized
                ).getOrThrow().jws.header.certificateChain?.flatMap {
                    it.toAuthorityKeyIdentifiers()
                } ?: listOf()

                is SubjectCredentialStore.StoreEntry.Vc -> JwsSigned.deserialize(
                    VerifiableCredentialJws.serializer(),
                    it.vcSerialized,
                    vckJsonSerializer
                ).getOrThrow().header.certificateChain?.flatMap {
                    it.toAuthorityKeyIdentifiers()
                } ?: listOf()
            }
        }
    )

    private fun X509Certificate.toAuthorityKeyIdentifiers() = tbsCertificate.extensions?.filter {
        // take all authority key identifiers from chain, assuming chain is validated elsewhere
        it.oid == KnownOIDs.authorityKeyIdentifier_2_5_29_35
    }?.map {
        DCQLAuthorityKeyIdentifier(it.value.asOctetString().content)
    } ?: listOf()
}