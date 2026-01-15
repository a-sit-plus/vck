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
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.Asn1PrimitiveOctetString
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.authorityKeyIdentifier_2_5_29_35
import at.asitplus.signum.indispensable.asn1.decodeRethrowing
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.decode
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
                    X509Certificate.decodeFromByteArray(it)?.getAuthorityKeyIdentifier() ?: listOf()
                } ?: listOf()

                is SubjectCredentialStore.StoreEntry.SdJwt -> SdJwtSigned.parseCatching(
                    it.vcSerialized
                ).getOrThrow().jws.header.certificateChain?.flatMap {
                    it.getAuthorityKeyIdentifier()
                } ?: listOf()

                is SubjectCredentialStore.StoreEntry.Vc -> JwsSigned.deserialize(
                    VerifiableCredentialJws.serializer(),
                    it.vcSerialized,
                    vckJsonSerializer
                ).getOrThrow().header.certificateChain?.flatMap {
                    it.getAuthorityKeyIdentifier()
                } ?: listOf()
            }
        }
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