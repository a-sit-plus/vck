package at.asitplus.wallet.lib

import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.data.VcDataModelConstants
import com.benasher44.uuid.uuid4

typealias RequestedAttributes = Set<String>
typealias RequestedAttributePaths = Set<DCQLClaimsPathPointer>

interface RequestOptions {
    val state: String
}

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
    val attributePaths: RequestedAttributePaths? = null,
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
    val optionalAttributePaths: RequestedAttributePaths? = null,
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
     * Requests [requestedMdocClaims] and [requestedOptionalMdocClaims] alike: a `DocRequest` marks no data element
     * as optional (ISO/IEC 18013-5:2021, 8.3.2.1.2.1), and the mdoc may answer with error codes for data elements
     * it does not return (ISO/IEC 18013-5:2021, 8.3.2.1.2.2).
     */
    fun toDocRequest(): DocRequest {
        require(credentialScheme is IsoMdocCredentialScheme) {
            "ISO Device Retrieval can only be created for IsoMdoc credential schemes"
        }
        require(representation == ISO_MDOC) {
            "ISO Device Retrieval can only be created for the representation ISO_MDOC, not $representation"
        }
        val namespaces = (requestedMdocClaims + requestedOptionalMdocClaims)
            .groupBy({ it.namespace }, { SingleItemsRequest(dataElementIdentifier = it.claimName, intentToRetain = false) })
            .mapValues { ItemsRequestList(it.value) }
        return DocRequest(
            itemsRequest = ByteStringWrapper(
                ItemsRequest(
                    docType = credentialScheme.isoDocType,
                    namespaces = namespaces,
                ),
            ),
        )
    }

    fun effectiveRequestedAttributePaths(): RequestedAttributePaths =
        attributePaths ?: emptySet()

    fun effectiveRequestedOptionalAttributePaths(): RequestedAttributePaths =
        optionalAttributePaths ?: emptySet()

    private fun RequestedAttributePaths?.toMdocClaims(): Set<MdocClaimReference> =
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
fun DCQLClaimsPathPointer.toVcJwtClaimPath(): DCQLClaimsPathPointer {
    val firstSegment = segments.first()
    val alreadyQualified = firstSegment is DCQLClaimsPathPointerSegment.NameSegment &&
            firstSegment.name == VcDataModelConstants.CREDENTIAL_SUBJECT
    return if (alreadyQualified) this
    else DCQLClaimsPathPointer(VcDataModelConstants.CREDENTIAL_SUBJECT) + this
}
