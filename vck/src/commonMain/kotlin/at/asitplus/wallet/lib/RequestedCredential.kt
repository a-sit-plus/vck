package at.asitplus.wallet.lib

import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
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
     * An SD-JWT VC (format `dc+sd-jwt`) of the type [vct] (OpenID4VP 1.0, B.3.5). The paths of [claims] start at the
     * root of the processed SD-JWT VC payload.
     */
    data class SdJwt @JvmOverloads constructor(
        val vct: String,
        val claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
        override val id: String = uuid4().toString(),
    ) : RequestedCredential {
        init {
            requireCredentialQueryId(id)
        }

        /** Requests every claim of [claims]. */
        @JvmOverloads
        constructor(
            vct: String,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString()
        ) : this(
            vct = vct,
            claims = ClaimSelection.All(claims.toList()),
            id = id
        )

        /** Requests an SD-JWT VC of the [CredentialScheme.sdJwtType] of [scheme]. */
        @JvmOverloads
        constructor(
            scheme: SdJwtCredentialScheme,
            claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
            id: String = uuid4().toString(),
        ) : this(
            vct = scheme.sdJwtType,
            claims = claims,
            id = id
        )

        /** Requests an SD-JWT VC of the [CredentialScheme.sdJwtType] of [scheme] with every claim of [claims]. */
        @JvmOverloads
        constructor(
            scheme: SdJwtCredentialScheme,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString()
        ) : this(
            vct = scheme.sdJwtType,
            claims = ClaimSelection.All(claims.toList()),
            id = id
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
    ) : RequestedCredential {
        init {
            requireCredentialQueryId(id)
        }

        /** Requests every claim of [claims]. */
        @JvmOverloads
        constructor(
            type: String,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString()
        ) : this(
            type = type,
            claims = ClaimSelection.All(claims.toList()),
            id = id
        )

        /** Requests a VC-JWT of the [CredentialScheme.vcType] of [scheme]. */
        @JvmOverloads
        constructor(
            scheme: VcJwtCredentialScheme,
            claims: ClaimSelection<JsonClaimReference> = ClaimSelection.All(),
            id: String = uuid4().toString(),
        ) : this(
            type = scheme.vcType,
            claims = claims,
            id = id
        )

        /** Requests a VC-JWT of the [CredentialScheme.vcType] of [scheme] with every claim of [claims]. */
        @JvmOverloads
        constructor(
            scheme: VcJwtCredentialScheme,
            vararg claims: JsonClaimReference,
            id: String = uuid4().toString()
        ) : this(
            type = scheme.vcType,
            claims = ClaimSelection.All(claims.toList()),
            id = id
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
    ) : RequestedCredential {

        /** Requests every data element of [claims]. */
        @JvmOverloads
        constructor(
            docType: String,
            vararg claims: MdocClaimReference,
            intentToRetain: Set<MdocClaimReference> = setOf(),
            id: String = uuid4().toString(),
        ) : this(
            docType = docType,
            claims = ClaimSelection.All(claims.toList()),
            intentToRetain = intentToRetain,
            id = id
        )

        /** Requests an mdoc of the [CredentialScheme.isoDocType] of [scheme]. */
        @JvmOverloads
        constructor(
            scheme: IsoMdocCredentialScheme,
            claims: ClaimSelection<MdocClaimReference> = ClaimSelection.All(),
            intentToRetain: Set<MdocClaimReference> = setOf(),
            id: String = uuid4().toString(),
        ) : this(
            docType = scheme.isoDocType,
            claims = claims,
            intentToRetain = intentToRetain,
            id = id
        )

        /** Requests an mdoc of the [CredentialScheme.isoDocType] of [scheme] with every data element of [claims]. */
        @JvmOverloads
        constructor(
            scheme: IsoMdocCredentialScheme,
            vararg claims: MdocClaimReference,
            intentToRetain: Set<MdocClaimReference> = setOf(),
            id: String = uuid4().toString(),
        ) : this(
            docType = scheme.isoDocType,
            claims = ClaimSelection.All(claims.toList()),
            intentToRetain = intentToRetain,
            id = id
        )

        init {
            requireCredentialQueryId(id)
            val notRequested = intentToRetain - claims.claims.toSet()
            require(notRequested.isEmpty()) { "Data elements to retain are not requested: $notRequested" }
        }

        /**
         * The `DocRequest` of ISO/IEC 18013-5:2021, 8.3.2.1.2.1 for this mdoc, requesting only the data elements of
         * [ClaimSelection.All.required]: an `ItemsRequest` marks no data element as optional, so one of
         * [ClaimSelection.All.ifAvailable] would be requested like a required one, and a holder lacking it would not
         * present the mdoc at all. Data elements if available are requested by the DCQL query only.
         *
         * Fails without any required data element, as an `ItemsRequest` requests at least one name space with at
         * least one data element (`NameSpaces = {+ NameSpace => DataElements}`, `DataElements = {+ DataElement =>
         * IntentToRetain}`, ISO/IEC 18013-5:2021, 8.3.2.1.2.1).
         */
        fun toDocRequest(): DocRequest {
            val dataElements = when (val selection = claims) {
                is ClaimSelection.All -> selection.required
            }
            require(dataElements.isNotEmpty()) { "An ISO DocRequest requests at least one data element" }
            val namespaces = dataElements
                .groupBy(
                    keySelector = { it.namespace },
                    valueTransform = { SingleItemsRequest(it.claimName, it in intentToRetain) },
                )
                .mapValues { ItemsRequestList(it.value) }
            return DocRequest(ByteStringWrapper(ItemsRequest(docType = docType, namespaces = namespaces)))
        }
    }
}

/** Requires a valid ID of a DCQL Credential Query, see [RequestedCredential.id]. */
private fun requireCredentialQueryId(id: String) {
    DCQLCredentialQueryIdentifier(id)
}
