package at.asitplus.wallet.lib

import at.asitplus.iso.DocRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.JsonClaimReference
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.VcDataModelConstants
import com.benasher44.uuid.uuid4

@Deprecated(
    "Request claims as JsonClaimReferences or MdocClaimReferences of a RequestedCredential",
    ReplaceWith("Set<DCQLClaimsPathPointer>", "at.asitplus.openid.dcql.DCQLClaimsPathPointer"),
)
typealias RequestedAttributePaths = Set<DCQLClaimsPathPointer>

interface RequestOptions {
    val state: String
}

/**
 * A credential to request in one representation, with claims paths whose meaning depends on the [representation].
 *
 * Deprecated: request a typed [RequestedCredential] instead, which [toRequestedCredential] converts this to.
 */
@Deprecated(
    "Request a RequestedCredential.SdJwt, VcJwt, or Mdoc, see toRequestedCredential(): VC-JWT claims paths start at " +
            "the root of the VC, mdoc data elements are MdocClaimReferences, and optional paths are " +
            "ClaimSelection.All.ifAvailable"
)
data class RequestOptionsCredential(
    /** Credential type to request, or `null` to make no restrictions. */
    val credentialScheme: CredentialScheme,
    /** Required representation, see [CredentialRepresentation]. */
    val representation: CredentialRepresentation = PLAIN_JWT,
    /** ID to be used in [DCQLCredentialQuery] */
    val id: String = uuid4().toString(),
    /**
     * List of JSON claim paths that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions.
     *
     * Use `DCQLClaimsPathPointer("address.region")` to request a flat claim with a literal dot in its name.
     * Use `DCQLClaimsPathPointer("address", "region")` to request `region` nested inside `address`.
     *
     * For [PLAIN_JWT], paths are relative to `credentialSubject`, see [toVcJwtClaimPath].
     * For [ISO_MDOC], see [requestedMdocClaims].
     */
    val attributePaths: Set<DCQLClaimsPathPointer>? = null,
    /**
     * List of JSON claim paths that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional), or `null` to make no restrictions.
     *
     * Use `DCQLClaimsPathPointer("address.region")` to request a flat claim with a literal dot in its name.
     * Use `DCQLClaimsPathPointer("address", "region")` to request `region` nested inside `address`.
     *
     * For [PLAIN_JWT], paths are relative to `credentialSubject`, see [toVcJwtClaimPath].
     * For [ISO_MDOC], see [requestedOptionalMdocClaims].
     */
    val optionalAttributePaths: Set<DCQLClaimsPathPointer>? = null,
) {

    /**
     * The data elements an [ISO_MDOC] request asks for with [attributePaths], empty for other representations.
     *
     * ISO/IEC 18013-5:2021, 8.3.2.1.2.1 requests a data element by its name space and data element identifier, so
     * each pointer holds either the data element identifier in the [CredentialScheme.isoNamespace] of
     * [credentialScheme], e.g. `DCQLClaimsPathPointer("given_name")`, or the name space and the data element
     * identifier, e.g. `DCQLClaimsPathPointer("org.iso.18013.5.1", "given_name")`. Any other pointer is rejected
     * when constructing this request.
     */
    val requestedMdocClaims: Set<MdocClaimReference> = attributePaths.toMdocClaims()

    /** The data elements an [ISO_MDOC] request asks for with [optionalAttributePaths], see [requestedMdocClaims]. */
    val requestedOptionalMdocClaims: Set<MdocClaimReference> = optionalAttributePaths.toMdocClaims()

    /**
     * This request as a [RequestedCredential] of its [representation], with the claims of [attributePaths] required
     * and the claims of [optionalAttributePaths] requested if available ([ClaimSelection.All.ifAvailable]); a path in
     * both is required. For [PLAIN_JWT], the paths are prefixed with `credentialSubject` (see [toVcJwtClaimPath]), for
     * [ISO_MDOC] they are read as data elements (see [requestedMdocClaims]).
     *
     * Fails if [credentialScheme] has no type identifier for [representation].
     */
    fun toRequestedCredential(): RequestedCredential = when (representation) {
        PLAIN_JWT -> RequestedCredential.VcJwt(
            type = requireNotNull(credentialScheme.vcType) { "The credential scheme has no VC type" },
            claims = jsonClaimSelection { JsonClaimReference(it.toVcJwtClaimPath()) },
            id = id,
        )

        SD_JWT -> RequestedCredential.SdJwt(
            vct = requireNotNull(credentialScheme.sdJwtType) { "The credential scheme has no SD-JWT VC type" },
            claims = jsonClaimSelection { JsonClaimReference(it) },
            id = id,
        )

        ISO_MDOC -> RequestedCredential.Mdoc(
            docType = requireNotNull(credentialScheme.isoDocType) { "The credential scheme has no ISO document type" },
            claims = ClaimSelection.All(
                required = requestedMdocClaims,
                ifAvailable = requestedOptionalMdocClaims - requestedMdocClaims,
            ),
            id = id,
        )
    }

    /**
     * Requests only the data elements of [requestedMdocClaims], not [requestedOptionalMdocClaims], see
     * [RequestedCredential.Mdoc.toDocRequest], which fails without any required data element.
     *
     * Fails for another [representation] than [ISO_MDOC], and, as [toRequestedCredential] does, if [credentialScheme]
     * has no [CredentialScheme.isoDocType].
     */
    fun toDocRequest(): DocRequest {
        require(representation == ISO_MDOC) {
            "ISO Device Retrieval can only be created for the representation ISO_MDOC, not $representation"
        }
        return (toRequestedCredential() as RequestedCredential.Mdoc).toDocRequest()
    }

    /**
     * The claims of [attributePaths] required and those of [optionalAttributePaths] requested if available, each
     * converted with [toClaim] before an optional claim that is also required is dropped: two paths may name the same
     * claim, e.g. `["given_name"]` and `["credentialSubject", "given_name"]` for a VC-JWT.
     */
    private fun jsonClaimSelection(
        toClaim: (DCQLClaimsPathPointer) -> JsonClaimReference,
    ): ClaimSelection.All<JsonClaimReference> {
        val required = effectiveRequestedAttributePaths().mapTo(linkedSetOf(), toClaim)
        return ClaimSelection.All(
            required = required,
            ifAvailable = effectiveRequestedOptionalAttributePaths().mapTo(linkedSetOf(), toClaim) - required,
        )
    }

    fun effectiveRequestedAttributePaths(): Set<DCQLClaimsPathPointer> =
        attributePaths ?: emptySet()

    fun effectiveRequestedOptionalAttributePaths(): Set<DCQLClaimsPathPointer> =
        optionalAttributePaths ?: emptySet()

    private fun Set<DCQLClaimsPathPointer>?.toMdocClaims(): Set<MdocClaimReference> =
        if (this == null || representation != ISO_MDOC) emptySet()
        else mapTo(linkedSetOf()) { it.toMdocClaim() }

    private fun DCQLClaimsPathPointer.toMdocClaim(): MdocClaimReference {
        val names = segments.map {
            require(it is DCQLClaimsPathPointerSegment.NameSegment) {
                "An ISO mdoc data element is requested by its name space and data element identifier, not by $this"
            }
            it.name
        }
        return when (names.size) {
            1 -> MdocClaimReference(
                namespace = requireNotNull(credentialScheme.isoNamespace) {
                    "The credential scheme has no ISO name space for the data element identifier in $this"
                },
                claimName = names.single(),
            )

            2 -> MdocClaimReference(namespace = names.first(), claimName = names.last())
            else -> throw IllegalArgumentException(
                "An ISO mdoc data element is requested by its data element identifier, optionally preceded by its " +
                        "name space, not by $this"
            )
        }
    }
}

/**
 * Qualifies a requested attribute path for a W3C VC: DCQL claims paths match on the root of the VC (OpenID4VP 1.0,
 * B.1.2), while requested attributes name claims about the subject like for the other representations, so
 * `credentialSubject` is prefixed unless the path already starts with it, e.g. `["given_name"]` becomes
 * `["credentialSubject", "given_name"]` as in OpenID4VP 1.0, B.1.3.1.4.
 */
internal fun DCQLClaimsPathPointer.toVcJwtClaimPath(): DCQLClaimsPathPointer {
    val firstSegment = segments.first()
    val alreadyQualified = firstSegment is DCQLClaimsPathPointerSegment.NameSegment &&
            firstSegment.name == VcDataModelConstants.CREDENTIAL_SUBJECT
    return if (alreadyQualified) this
    else DCQLClaimsPathPointer(VcDataModelConstants.CREDENTIAL_SUBJECT) + this
}
