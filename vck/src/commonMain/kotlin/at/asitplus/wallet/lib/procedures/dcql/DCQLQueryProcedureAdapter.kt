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

import at.asitplus.KmmResult
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.openid.dcql.DCQLAuthorityKeyIdentifier
import at.asitplus.openid.dcql.DCQLCredentialClaimStructure
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.openid.dcql.DCQLIsoMdocCredential
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.openid.dcql.DCQLQueryMatchingResult
import at.asitplus.openid.dcql.DCQLQueryResponse
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
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.validation.ValidatedPresentation
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.jvm.JvmInline
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonUnquotedLiteral
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborArray
import net.orandja.obor.data.CborBoolean
import net.orandja.obor.data.CborBytes
import net.orandja.obor.data.CborBytesIndefinite
import net.orandja.obor.data.CborFloat
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborMapEntry
import net.orandja.obor.data.CborNegative
import net.orandja.obor.data.CborObject
import net.orandja.obor.data.CborPositive
import net.orandja.obor.data.CborTagged
import net.orandja.obor.data.CborText
import net.orandja.obor.data.CborTextIndefinite

@JvmInline
value class DCQLQueryAdapter(val dcqlQuery: DCQLQuery) {
    suspend fun select(
        credentials: List<SubjectCredentialStore.StoreEntry>
    ): DCQLQueryMatchingResult = dcqlQuery.findCredentialQueryMatches(
        availableCredentials = credentials.map {
            it.toDCQLCredential()
        }
    )

    fun checkSubmissionRequirements(
        queryResponse: DCQLQueryResponse<VerifyPresentationResult>,
    ) = dcqlQuery.checkSubmissionRequirements(
        dcqlQueryResponse = queryResponse,
        parseSdJwtCredential = { it.toDCQLSdJwtCredential() },
        parseVcJwsCredential = { it.toDCQLVcJwsCredential() },
        parseIsoMdocCredential = { it.toDCQLIsoMdocCredential() },
    )

    /**
     * Checks the submission requirements of the query, i.e. its credential sets and every credential query, over the
     * [accepted] presentations only, by the credential query they answer: a rejected presentation counts as if it had
     * not been submitted, like a credential that does not match its query (OpenID4VP 1.0, 6.4.2), so the response is
     * only rejected if the request can not be satisfied without it.
     */
    fun checkAcceptedSubmissions(
        accepted: Map<DCQLCredentialQueryIdentifier, List<ValidatedPresentation>>,
    ): KmmResult<Unit> = dcqlQuery.checkSubmissionRequirements(
        dcqlQueryResponse = DCQLQueryResponse(accepted.filterValues { it.isNotEmpty() }),
        parseSdJwtCredential = { it.toDCQLSdJwtCredential() },
        parseVcJwsCredential = { it.toDCQLVcJwsCredential() },
        parseIsoMdocCredential = { it.toDCQLIsoMdocCredential() },
    )

    private fun ValidatedPresentation.toDCQLSdJwtCredential(): DCQLSdJwtCredential = when (this) {
        is ValidatedPresentation.SdJwt -> DCQLSdJwtCredential(
            claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(credential.reconstructedJsonObject),
            satisfiesCryptographicHolderBinding = credential.credential.confirmationClaim != null,
            authorityKeyIdentifiers = credential.sdJwtSigned.jws.jwsHeader.certificateChain
                ?.flatMap { it.getAuthorityKeyIdentifier() } ?: listOf(),
            type = credential.credential.verifiableCredentialType,
        )

        else -> throw IllegalArgumentException("Presentation is no SD-JWT VC")
    }

    // The issuer's certificate chain is not kept for VC-JWTs, so trusted_authorities can not be matched for them.
    private fun ValidatedPresentation.toDCQLVcJwsCredential(): DCQLVcJwsCredential = when (this) {
        is ValidatedPresentation.VpJwt -> {
            require(credentials.size == 1) {
                "Expected one verifiable credential per presentation, but got ${credentials.size}"
            }
            credentials.single().credential.toDCQLCredential(satisfiesCryptographicHolderBinding = null)
        }

        is ValidatedPresentation.VcJwt ->
            credential.credential.toDCQLCredential(satisfiesCryptographicHolderBinding = false)
        else -> throw IllegalArgumentException("Presentation is no VC-JWT")
    }

    private fun VerifiableCredentialJws.toDCQLCredential(satisfiesCryptographicHolderBinding: Boolean?) =
        DCQLVcJwsCredential(
            satisfiesCryptographicHolderBinding = satisfiesCryptographicHolderBinding ?: !subject.isNullOrEmpty(),
            types = vc.type,
            authorityKeyIdentifiers = listOf(),
            claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(
                CredentialToJsonConverter.toJsonElement(this)
            ),
        )

    // Every item of an accepted document has been validated, there is no partial acceptance.
    private fun ValidatedPresentation.toDCQLIsoMdocCredential(): DCQLIsoMdocCredential = when (this) {
        is ValidatedPresentation.MdocDocument -> with(credential.issuerSigned) {
            DCQLIsoMdocCredential(
                claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(
                    namespaces?.mapValues { namespace ->
                        namespace.value.entries.associate { it.value.elementIdentifier to it.toDcqlClaimValue() }
                    } ?: mapOf()
                ),
                documentType = document.docType,
                satisfiesCryptographicHolderBinding = issuerAuth.payload?.deviceKeyInfo != null,
                authorityKeyIdentifiers = issuerAuth.unprotectedHeader?.certificateChain?.flatMap {
                    X509Certificate.decodeFromByteArray(it)?.getAuthorityKeyIdentifier() ?: listOf()
                } ?: listOf(),
            )
        }

        else -> throw IllegalArgumentException("Presentation is no mdoc document")
    }

    private fun VerifyPresentationResult.toDCQLSdJwtCredential(): DCQLSdJwtCredential = when (this) {
        is VerifyPresentationResult.SuccessSdJwt -> toDCQLCredential()
        else -> throw IllegalArgumentException("Cannot create DCQLSdJwtCredential from validation result $this")
    }

    private fun VerifyPresentationResult.toDCQLVcJwsCredential(): DCQLVcJwsCredential = when (this) {
        is VerifyPresentationResult.Success -> toDCQLCredential()
        is VerifyPresentationResult.SuccessUnsigned -> toDCQLCredential()
        else -> throw IllegalArgumentException("Cannot create DCQLVcJwsCredential from validation result $this")
    }

    private fun VerifyPresentationResult.toDCQLIsoMdocCredential(): DCQLIsoMdocCredential = when (this) {
        is VerifyPresentationResult.SuccessIso -> toDCQLCredential()
        else -> throw IllegalArgumentException("Cannot create DCQLIsoMdocCredential from validation result $this")
    }

    private fun VerifyPresentationResult.SuccessUnsigned.toDCQLCredential(): DCQLVcJwsCredential {
        require(vc.freshnessSummary.isFresh) {
            "Expected credential to be fresh, but was ${vc.freshnessSummary}"
        }
        return DCQLVcJwsCredential(
            satisfiesCryptographicHolderBinding = false,
            types = this.vc.vcJws.vc.type,
            authorityKeyIdentifiers = listOf(),
            claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(
                CredentialToJsonConverter.toJsonElement(vc.vcJws)
            )
        )
    }

    private fun VerifyPresentationResult.Success.toDCQLCredential(): DCQLVcJwsCredential {
        require(vp.invalidVerifiableCredentials.isEmpty()) {
            "Expected only valid verifiable credentials, but got invalid credentials ${vp.invalidVerifiableCredentials}"
        }
        require(vp.notVerifiablyFreshVerifiableCredentials.isEmpty()) {
            "Unable to check freshness of credentials ${vp.notVerifiablyFreshVerifiableCredentials}"
        }
        require(vp.freshVerifiableCredentials.size == 1) {
            "Expected only 1 valid verifiable credential per presentation, but got ${vp.freshVerifiableCredentials}"
        }
        val credential = vp.freshVerifiableCredentials.first()

        return DCQLVcJwsCredential(
            satisfiesCryptographicHolderBinding = !credential.vcJws.subject.isNullOrEmpty(),
            types = credential.vcJws.vc.type,
            authorityKeyIdentifiers = vp.jws.jws.jwsHeader.certificateChain?.flatMap {
                it.getAuthorityKeyIdentifier()
            } ?: listOf(),
            claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(
                CredentialToJsonConverter.toJsonElement(credential.vcJws)
            )
        )
    }

    private fun VerifyPresentationResult.SuccessIso.toDCQLCredential(): DCQLIsoMdocCredential {
        require(documents.size == 1) {
            "Expected only one document per credential, but received ${documents.size}: $documents"
        }
        with(documents.first()) {
            return DCQLIsoMdocCredential(
                DCQLCredentialClaimStructure.IsoMdocStructure(
                    document.issuerSigned.namespaces?.mapValues { namespace ->
                        namespace.value.entries
                            .filter { it.value in validItems }
                            .associate {
                                it.value.elementIdentifier to it.toDcqlClaimValue()
                            }
                    } ?: mapOf()
                ),
                documentType = document.docType,
                satisfiesCryptographicHolderBinding = document.issuerSigned.issuerAuth.payload?.deviceKeyInfo != null,
                authorityKeyIdentifiers = document.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.flatMap {
                    X509Certificate.decodeFromByteArray(it)?.getAuthorityKeyIdentifier() ?: listOf()
                } ?: listOf(),
            )
        }
    }

    private fun VerifyPresentationResult.SuccessSdJwt.toDCQLCredential() = DCQLSdJwtCredential(
        claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(reconstructedJsonObject),
        satisfiesCryptographicHolderBinding = verifiableCredentialSdJwt.confirmationClaim != null,
        authorityKeyIdentifiers = sdJwtSigned.jws.jwsHeader.certificateChain?.flatMap {
            it.getAuthorityKeyIdentifier()
        } ?: listOf(),
        type = verifiableCredentialSdJwt.verifiableCredentialType,
    )


    private suspend fun SubjectCredentialStore.StoreEntry.toDCQLCredential() = when (this) {
        is SubjectCredentialStore.StoreEntry.Iso -> toDCQLCredential()
        is SubjectCredentialStore.StoreEntry.SdJwt -> toDCQLCredential()
        is SubjectCredentialStore.StoreEntry.Vc -> toDCQLCredential()
    }

    private suspend fun SubjectCredentialStore.StoreEntry.Iso.toDCQLCredential() = DCQLIsoMdocCredential(
        claimStructure = DCQLCredentialClaimStructure.IsoMdocStructure(
            issuerSigned.namespaces?.mapValues { entry ->
                entry.value.entries.associate {
                    it.value.elementIdentifier to it.toDcqlClaimValue()
                }
            } ?: mapOf()
        ),
        satisfiesCryptographicHolderBinding = issuerSigned.issuerAuth.payload?.deviceKeyInfo != null,
        authorityKeyIdentifiers = issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.flatMap {
            X509Certificate.decodeFromByteArray(it)?.getAuthorityKeyIdentifier() ?: listOf()
        } ?: listOf(),
        documentType = schemeIdentifier
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
        type = sdJwt.verifiableCredentialType,
    )

    private fun SubjectCredentialStore.StoreEntry.Vc.toDCQLCredential() = DCQLVcJwsCredential(
        claimStructure = DCQLCredentialClaimStructure.JsonBasedStructure(
            CredentialToJsonConverter.toJsonElement(this.vc)
        ),
        satisfiesCryptographicHolderBinding = !vc.subject.isNullOrEmpty(),
        authorityKeyIdentifiers = JwsCompactTyped<VerifiableCredentialJws>(
            vcSerialized
        ).jws.jwsHeader.certificateChain?.flatMap {
            it.getAuthorityKeyIdentifier()
        } ?: listOf(),
        types = vc.vc.type,
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
 * [RFC 5280 4.2.1.1. Authority Key Identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1)
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

/**
 * The value of this ISO mdoc data element for DCQL matching, converted to JSON. OpenID4VP 1.0, 6.3: "If a Wallet
 * implements value matching and the Credential being matched is an ISO mdoc-based credential, the CBOR value used for
 * matching MUST first be converted to JSON, following the advice given in Section 6.1 of [RFC8949]."
 *
 * The original CBOR item of the element value is converted, see [toRfc8949Json], not the decoded value, so that e.g. a
 * date-time keeps its string as issued and a scheme-specific type its CBOR representation. If the item can not be
 * read, the value is [JsonNull], so that the data element is still present, but it can not match `values`.
 */
internal fun ByteStringWrapper<IssuerSignedItem>.toDcqlClaimValue(): JsonElement = catchingUnwrapped {
    (Cbor.decodeFromByteArray<CborObject>(serialized) as CborMap).elements
        .first { (it.key as? CborText)?.value == ELEMENT_VALUE }
        .value.toRfc8949Json()
}.getOrNull() ?: JsonNull

/** The serial name of the element value in an `IssuerSignedItem`, ISO/IEC 18013-5, 8.3.2.1.2.2. */
private const val ELEMENT_VALUE = "elementValue"

/**
 * Converts this CBOR item to JSON as RFC 8949, 6.1 advises:
 * - An integer becomes a number, a text string a string, and a byte string a base64url string without padding.
 * - An array becomes an array, and a map an object, with keys that are not text strings converted to their JSON.
 * - `false`, `true` and `null` become their JSON counterparts. A floating-point number becomes a number, or `null` if
 *   it is not finite. Any other simple value, e.g. `undefined`, becomes `null`.
 * - A bignum (tags 2 and 3) becomes the base64url string of its byte string, prefixed by `~` if it is negative.
 * - An encoding hint (tags 21 to 23) encodes the byte strings it encloses in base64url, base64 or base16.
 * - Any other tag becomes the conversion of its content, e.g. a full-date (tag 1004) or date-time (tag 0) its string.
 */
@OptIn(ExperimentalSerializationApi::class)
internal fun CborObject.toRfc8949Json(
    byteEncoding: (ByteArray) -> String = { it.encodeToString(Base64UrlStrict) },
): JsonElement = when (this) {
    is CborPositive -> JsonUnquotedLiteral(value.toString())
    is CborNegative -> JsonUnquotedLiteral(
        if (value == ULong.MAX_VALUE) "-18446744073709551616" else "-${value + 1u}"
    )
    is CborBytes -> JsonPrimitive(byteEncoding(value))
    is CborBytesIndefinite -> JsonPrimitive(byteEncoding(byteStringOrNull()!!))
    is CborText -> JsonPrimitive(value)
    is CborTextIndefinite -> JsonPrimitive(value.joinToString("") { it.value })
    is CborArray -> JsonArray(elements.map { it.toRfc8949Json(byteEncoding) })
    is CborMap -> JsonObject(elements.associate {
        ((it.key as? CborText)?.value ?: it.key.toRfc8949Json(byteEncoding).toString()) to
                it.value.toRfc8949Json(byteEncoding)
    })
    is CborMapEntry -> JsonNull
    is CborBoolean -> JsonPrimitive(value)
    is CborFloat -> if (value.isFinite()) JsonPrimitive(value) else JsonNull
    is CborTagged -> when (tag) {
        2L -> value.byteStringOrNull()?.let { JsonPrimitive(it.encodeToString(Base64UrlStrict)) } ?: JsonNull
        3L -> value.byteStringOrNull()?.let { JsonPrimitive("~" + it.encodeToString(Base64UrlStrict)) } ?: JsonNull
        21L -> value.toRfc8949Json { it.encodeToString(Base64UrlStrict) }
        22L -> value.toRfc8949Json { it.encodeToString(Base64Strict) }
        23L -> value.toRfc8949Json { bytes ->
            bytes.joinToString("") { it.toUByte().toString(16).padStart(2, '0').uppercase() }
        }
        else -> value.toRfc8949Json(byteEncoding)
    }
    else -> JsonNull
}

/**
 * The bytes of this byte string, with the chunks of an indefinite-length byte string concatenated (RFC 8949,
 * 3.2.3), or null if this is no byte string.
 */
private fun CborObject.byteStringOrNull(): ByteArray? = when (this) {
    is CborBytes -> value
    is CborBytesIndefinite -> elements.fold(byteArrayOf()) { acc, it -> acc + it.value }
    else -> null
}
