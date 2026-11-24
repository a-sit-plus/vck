package at.asitplus.wallet.lib

import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ofCombinations
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.extensions.subjectKeyIdentifier
import com.benasher44.uuid.uuid4
import kotlin.jvm.JvmOverloads

/**
 * A credential requested from a holder, with the claims requested from it, in one of the credential formats.
 *
 * The constructors taking a credential scheme take the type identifier of the format from its typed subinterface of
 * [CredentialScheme], e.g. the [SdJwtCredentialScheme.sdJwtType].
 */
sealed interface RequestedCredential {
    /**
     * ID of the DCQL Credential Query (OpenID4VP 1.0, 6.1), a random UUID by default. Set a stable ID when it is
     * referenced from elsewhere, e.g. from the `credential_ids` of transaction data (OpenID4VP 1.0, 5.1), or in tests.
     * It "MUST be a non-empty string consisting of alphanumeric, underscore (_), or hyphen (-) characters" (ibid.),
     * which constructing a request checks.
     *
     * Two requests are equal only if their IDs are, so with the random default, `SdJwt("x") != SdJwt("x")`: to
     * request one credential in several options or sets of a [RequestedPresentation], pass the same instance, or
     * requests with the same ID.
     */
    val id: String

    /**
     * Whether several credentials may be presented for this request: DCQL `multiple` (OpenID4VP 1.0, 6.1), and ISO
     * `uniqueDocSetRequired = !multiple` (ISO/IEC DIS 18013-5:2026, 10.2.4).
     */
    val multiple: Boolean

    /**
     * Certificates of the authorities that certify the issuers the verifier accepts, e.g. the IACA certificates of
     * mDL issuers, or empty for any issuer. They are requested by their subject key identifiers, which the certificates
     * they issue carry as their authority key identifier (RFC 5280, 4.2.1.2): the DCQL `trusted_authorities` of type
     * `aki` (OpenID4VP 1.0, 6.1.1), and the ISO `issuerIdentifiers` (ISO/IEC DIS 18013-5:2026, 10.2.4), so a
     * credential matches if a certificate in its chain was issued by one of them. Constructing a request fails for a
     * certificate without a subject key identifier, which RFC 5280, 4.2.1.2 requires of every CA certificate.
     *
     * The wallet uses them to not present credentials the verifier would reject, which does not replace the verifier's
     * own trust validation: "Verifiers must verify that the issuer of a received presentation is trusted on their
     * own" (OpenID4VP 1.0, 6.1).
     */
    val trustedAuthorities: Set<X509Certificate>

    /**
     * An SD-JWT VC (format `dc+sd-jwt`) of the type [vct] (OpenID4VP 1.0, B.3.5). The paths of [claims] start at the
     * root of the processed SD-JWT VC payload.
     */
    data class SdJwt @JvmOverloads constructor(
        val vct: String,
        val claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
        override val id: String = uuid4().toString(),
        override val multiple: Boolean = false,
        override val trustedAuthorities: Set<X509Certificate> = setOf(),
    ) : RequestedCredential {
        init {
            requireCredentialQueryId(id)
            requireSubjectKeyIdentifiers(trustedAuthorities)
        }

        /** Requests every claim of [claims]. */
        @JvmOverloads
        constructor(
            vct: String,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            vct = vct,
            claims = ClaimSelection.All(claims.toSet()),
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        /** Requests an SD-JWT VC of the [CredentialScheme.sdJwtType] of [scheme]. */
        @JvmOverloads
        constructor(
            scheme: SdJwtCredentialScheme,
            claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            vct = scheme.sdJwtType,
            claims = claims,
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        /** Requests an SD-JWT VC of the [CredentialScheme.sdJwtType] of [scheme] with every claim of [claims]. */
        @JvmOverloads
        constructor(
            scheme: SdJwtCredentialScheme,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            vct = scheme.sdJwtType,
            claims = ClaimSelection.All(claims.toSet()),
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )
    }

    /**
     * A W3C VC signed as a JWT (format `jwt_vc_json`) of the type [type] (OpenID4VP 1.0, B.1.3.1).
     *
     * Claims of a VC-JWT are not selectively disclosable, so [claims] only decides which credential matches the
     * request, and the whole credential is presented (OpenID4VP 1.0, 6.4.1). The paths of [claims] start at the root
     * of the VC, e.g. `JsonClaimReference("credentialSubject", "given_name")` (OpenID4VP 1.0, B.1.2).
     */
    data class VcJwt @JvmOverloads constructor(
        val type: String,
        val claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
        override val id: String = uuid4().toString(),
        override val multiple: Boolean = false,
        override val trustedAuthorities: Set<X509Certificate> = setOf(),
    ) : RequestedCredential {
        init {
            requireCredentialQueryId(id)
            requireSubjectKeyIdentifiers(trustedAuthorities)
        }

        /** Requests every claim of [claims]. */
        @JvmOverloads
        constructor(
            type: String,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            type = type,
            claims = ClaimSelection.All(claims.toSet()),
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        /** Requests a VC-JWT of the [CredentialScheme.vcType] of [scheme]. */
        @JvmOverloads
        constructor(
            scheme: VcJwtCredentialScheme,
            claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            type = scheme.vcType,
            claims = claims,
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        /** Requests a VC-JWT of the [CredentialScheme.vcType] of [scheme] with every claim of [claims]. */
        @JvmOverloads
        constructor(
            scheme: VcJwtCredentialScheme,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            type = scheme.vcType,
            claims = ClaimSelection.All(claims.toSet()),
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )
    }

    /** An ISO mdoc (format `mso_mdoc`) of the document type [docType] (OpenID4VP 1.0, B.2.3). */
    data class Mdoc @JvmOverloads constructor(
        val docType: String,
        val claims: ClaimSelection<MdocClaimReference> = ClaimSelection.All(),
        /**
         * The requested data elements the verifier intends to retain, the `IntentToRetain` of the `DataElements` in the
         * `ItemsRequest` (ISO/IEC 18013-5:2021, 8.3.2.1.2.1) and the `intent_to_retain` of the DCQL claims query
         * (OpenID4VP 1.0, B.2.4). Each must be one of the requested [claims].
         */
        val intentToRetain: Set<MdocClaimReference> = setOf(),
        override val id: String = uuid4().toString(),
        override val multiple: Boolean = false,
        override val trustedAuthorities: Set<X509Certificate> = setOf(),
    ) : RequestedCredential {

        /** Requests every data element of [claims]. */
        @JvmOverloads
        constructor(
            docType: String,
            vararg claims: MdocClaimReference,
            intentToRetain: Set<MdocClaimReference> = setOf(),
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            docType = docType,
            claims = ClaimSelection.All(claims.toSet()),
            intentToRetain = intentToRetain,
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        /** Requests an mdoc of the [CredentialScheme.isoDocType] of [scheme]. */
        @JvmOverloads
        constructor(
            scheme: IsoMdocCredentialScheme,
            claims: ClaimSelection<MdocClaimReference> = ClaimSelection.All(),
            intentToRetain: Set<MdocClaimReference> = setOf(),
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            docType = scheme.isoDocType,
            claims = claims,
            intentToRetain = intentToRetain,
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        /** Requests an mdoc of the [CredentialScheme.isoDocType] of [scheme] with every data element of [claims]. */
        @JvmOverloads
        constructor(
            scheme: IsoMdocCredentialScheme,
            vararg claims: MdocClaimReference,
            intentToRetain: Set<MdocClaimReference> = setOf(),
            id: String = uuid4().toString(),
            multiple: Boolean = false,
            trustedAuthorities: Set<X509Certificate> = setOf(),
        ) : this(
            docType = scheme.isoDocType,
            claims = ClaimSelection.All(claims.toSet()),
            intentToRetain = intentToRetain,
            id = id,
            multiple = multiple,
            trustedAuthorities = trustedAuthorities,
        )

        init {
            requireCredentialQueryId(id)
            requireSubjectKeyIdentifiers(trustedAuthorities)
            val notRequested = intentToRetain - claims.allClaims
            require(notRequested.isEmpty()) { "Data elements to retain are not requested: $notRequested" }
        }

        /**
         * The `DocRequest` of this mdoc (ISO/IEC DIS 18013-5:2026, 10.2.3), see `ItemsRequest.ofCombinations`:
         *  - for [ClaimSelection.All], the data elements of [ClaimSelection.All.required]: ISO has no optional data
         *    element, so one of [ClaimSelection.All.ifAvailable], requested like a required one, would keep a holder
         *    lacking it from presenting the mdoc at all; they are requested by the DCQL query only
         *  - for [ClaimSelection.Alternatives], the common data elements and the first option, each data element of
         *    which has the other options as its alternatives (ibid., 10.2.4)
         *
         * Its `DocRequestInfo` has `uniqueDocSetRequired = !`[multiple], always set, as its "Presence … is recommended
         * for the mdoc reader", and the subject key identifiers of [trustedAuthorities] as `issuerIdentifiers`
         * (ibid., 10.2.4).
         *
         * Fails if nothing is requested, e.g. without required data elements, as an `ItemsRequest` requests at least
         * one data element (`NameSpaces = {+ NameSpace => DataElements}`, ibid., 10.2.3).
         */
        fun toDocRequest(): DocRequest {
            val combinations = when (val selection = claims) {
                is ClaimSelection.All -> Combinations(selection.required, listOf(selection.ifAvailable, setOf()))
                is ClaimSelection.Alternatives -> Combinations(selection.common, selection.options)
            }
            val itemsRequest = ItemsRequest.ofCombinations(
                docType = docType,
                common = combinations.common.toElementReferences(),
                options = combinations.options.map { it.toElementReferences() },
                intentToRetain = intentToRetain.toElementReferences(),
                requestInfo = DocRequestInfo(
                    uniqueDocSetRequired = !multiple,
                    issuerIdentifiers = trustedAuthorityKeyIdentifiers().ifEmpty { null },
                ),
            )
            return DocRequest(ByteStringWrapper(itemsRequest))
        }
    }
}

/** The [common] data elements and the [options] of which one is requested, see `ItemsRequest.ofCombinations`. */
private class Combinations(val common: Set<MdocClaimReference>, val options: List<Set<MdocClaimReference>>)

private fun Set<MdocClaimReference>.toElementReferences() =
    mapTo(linkedSetOf()) { ElementReference(it.namespace, it.claimName) }

/**
 * The subject key identifiers of the [RequestedCredential.trustedAuthorities], each the key identifier of the
 * authority key identifier of the certificates they issue (RFC 5280, 4.2.1.2), in their order.
 */
private fun RequestedCredential.trustedAuthorityKeyIdentifiers(): List<ByteArray> =
    trustedAuthorities.map { requireNotNull(it.subjectKeyIdentifier) { "A trusted authority has no key identifier" } }

/** Requires a subject key identifier of each of [trustedAuthorities], see [RequestedCredential.trustedAuthorities]. */
private fun requireSubjectKeyIdentifiers(trustedAuthorities: Set<X509Certificate>) {
    val without = trustedAuthorities.filter { it.subjectKeyIdentifier == null }
    require(without.isEmpty()) {
        "Trusted authorities are requested by their subject key identifiers, but ${without.size} have none"
    }
}

/** Requires a valid ID of a DCQL Credential Query, see [RequestedCredential.id]. */
private fun requireCredentialQueryId(id: String) {
    DCQLCredentialQueryIdentifier(id)
}
