package at.asitplus.wallet.lib.procedures.dcql

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications: Added jwt_vc_json DCQL support for Orange implementation
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * Modifications: According to the W3C Verifiable Credential Data Model 1.1 https://www.w3.org/TR/vc-data-model-1.1/#jwt-decoding
 * subject ("sub") can be null if vc.credentialSubject does not have an "id" key.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.openid.JwsCompactTyped
import at.asitplus.openid.dcql.DCQLAuthorityKeyIdentifier
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLIsoMdocCredential
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryMatchingResult
import at.asitplus.openid.dcql.DCQLSdJwtCredential
import at.asitplus.openid.dcql.DCQLVcJwsCredential
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decode
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlin.jvm.JvmInline

@JvmInline
value class DCQLQueryAdapter(val dcqlQuery: DCQLQuery) {
    fun select(
        credentials: List<SubjectCredentialStore.StoreEntry>
    ): DCQLQueryMatchingResult = dcqlQuery.findCredentialQueryMatches(
        availableCredentials = credentials.map {
            it.toDCQLCredential()
        }
    )

    private fun SubjectCredentialStore.StoreEntry.toDCQLCredential() = when (this) {
        is SubjectCredentialStore.StoreEntry.Iso -> toDCQLCredential()
        is SubjectCredentialStore.StoreEntry.SdJwt -> toDCQLCredential()
        is SubjectCredentialStore.StoreEntry.Vc -> toDCQLCredential()
    }

    private fun SubjectCredentialStore.StoreEntry.Iso.toDCQLCredential() = DCQLIsoMdocCredential(
        claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(
            issuerSigned.namespaces?.mapValues { entry ->
                entry.value.entries.associate {
                    it.value.elementIdentifier to it.value.elementValue
                }
            } ?: mapOf()
        ),
        satisfiesCryptographicHolderBinding = issuerSigned.issuerAuth.payload?.deviceKeyInfo != null,
        authorityKeyIdentifiers = issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.flatMap {
            X509Certificate.decodeFromByteArray(it)?.getAuthorityKeyIdentifier() ?: listOf()
        } ?: listOf(),
        documentType = scheme!!.isoDocType!!
    )

    private fun SubjectCredentialStore.StoreEntry.SdJwt.toDCQLCredential() = DCQLSdJwtCredential(
        claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(
            CredentialToJsonConverter.toJsonElement(this)
        ),
        satisfiesCryptographicHolderBinding = sdJwt.confirmationClaim != null,
        authorityKeyIdentifiers = SdJwtSigned.parseCatching(
            vcSerialized
        ).getOrThrow().jws.jwsHeader.certificateChain?.flatMap {
            it.getAuthorityKeyIdentifier()
        } ?: listOf(),
        type = scheme!!.sdJwtType!!
    )

    private fun SubjectCredentialStore.StoreEntry.Vc.toDCQLCredential() = DCQLVcJwsCredential(
        claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(
            CredentialToJsonConverter.toJsonElement(this)
        ),
        satisfiesCryptographicHolderBinding = !vc.subject.isNullOrEmpty(),
        authorityKeyIdentifiers = JwsCompactTyped<VerifiableCredentialJws>(
            vcSerialized
        ).jws.jwsHeader.certificateChain?.flatMap {
            it.getAuthorityKeyIdentifier()
        } ?: listOf(),
        types = vc.vc.type.toList(),
    )

    // take all authority key identifiers from chain, assuming chain is validated elsewhere
    private fun X509Certificate.getAuthorityKeyIdentifier() = tbsCertificate.extensions?.filter {
        it.oid == KnownOIDs.authorityKeyIdentifier_2_5_29_35
    }?.mapNotNull {
        AuthorityKeyIdentifier.decodeFromDerSafe(it.value.asEncapsulatingOctetString().content)
            .getOrNull()?.keyIdentifier?.let { DCQLAuthorityKeyIdentifier(it) }
    } ?: listOf()
}

/**
 * To be moved into Signum.
 *
 * [RFC 5280 4.2.1.1. Authority Key Identifier](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.1)
 * ```
 *    id-ce-authorityKeyIdentifier OBJECT IDENTIFIER ::=  { id-ce 35 }
 *
 *    AuthorityKeyIdentifier ::= SEQUENCE {
 *       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
 *
 *    KeyIdentifier ::= OCTET STRING
 * ```
 */
class AuthorityKeyIdentifier(
    val keyIdentifier: ByteArray? = null,
    val authorityCertIssuer: Asn1Element? = null,
    val certificateSerial: ByteArray? = null,
) : Asn1Encodable<Asn1Sequence>, Identifiable {

    override val oid: ObjectIdentifier get() = Companion.oid

    override fun encodeToTlv() = Asn1.Sequence {
        keyIdentifier?.let { +(Asn1.OctetString(it) withImplicitTag 0UL) }
        authorityCertIssuer?.let { +(it withImplicitTag 1UL) }
        certificateSerial?.let { +(Asn1.OctetString(it) withImplicitTag 2UL) }
    }

    companion object : Asn1Decodable<Asn1Sequence, AuthorityKeyIdentifier>, Identifiable {
        override val oid: ObjectIdentifier = KnownOIDs.authorityKeyIdentifier_2_5_29_35

        override fun doDecode(src: Asn1Sequence): AuthorityKeyIdentifier = src.decodeRethrowing {
            val contents = listOfNotNull(nextOrNull(), nextOrNull(), nextOrNull())
            val keyIdentifier = contents.firstOrNull { it.tag.tagValue == 0uL }?.asPrimitive()
                ?.decode(Asn1Element.Tag(0UL, constructed = false, tagClass = TagClass.CONTEXT_SPECIFIC)) { it }
            val authorityCertIssuer = contents.firstOrNull { it.tag.tagValue == 1uL }
            val authorityCertSerialNumber = contents.firstOrNull { it.tag.tagValue == 2uL }?.asPrimitive()?.content
            AuthorityKeyIdentifier(keyIdentifier, authorityCertIssuer, authorityCertSerialNumber)
        }

    }
}