package at.asitplus.wallet.lib

import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.openid.dcql.DCQLClaimsPathPointer
import at.asitplus.openid.dcql.DCQLClaimsPathPointerSegment
import at.asitplus.openid.dcql.DCQLCredentialQuery
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
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
     */
    val attributePaths: RequestedAttributePaths? = null,
    /**
     * List of JSON claim paths that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional), or `null` to make no restrictions.
     *
     * Use `DCQLClaimsPathPointer("address.region")` to request a flat claim with a literal dot in its name.
     * Use `DCQLClaimsPathPointer("address", "region")` to request `region` nested inside `address`.
     */
    val optionalAttributePaths: RequestedAttributePaths? = null,
) {

    fun toDocRequest(): DocRequest {
        require(credentialScheme is IsoMdocCredentialScheme) {
            "ISO Device Retrieval can only be created for IsoMdoc credential schemes"
        }
        val effectiveAttributes = effectiveRequestedAttributePaths()
        require(effectiveAttributes.all { it.segments.all { it is DCQLClaimsPathPointerSegment.NameSegment } }) {
            "ISO mdoc requested attribute paths must contain only name segments"
        }
        // Merge (don't overwrite) entries that land in the same namespace, e.g. a two-segment path whose namespace
        // equals the scheme's default namespace plus one-segment paths under that same default namespace.
        val effectiveRequest = (effectiveAttributes.namespacedItems() + effectiveAttributes.singleClaimsItems())
            .groupBy({ it.first }, { it.second })
            .mapValues { (_, lists) -> ItemsRequestList(lists.flatMap { it.entries }) }
        return DocRequest(
            itemsRequest = ByteStringWrapper(
                ItemsRequest(
                    docType = credentialScheme.isoDocType,
                    namespaces = effectiveRequest
                ),
            ),
        )
    }

    private fun RequestedAttributePaths.namespacedItems(): List<Pair<String, ItemsRequestList>> =
        filter { it.segments.all { it is DCQLClaimsPathPointerSegment.NameSegment } }
            .filter { it.segments.size == 2 }
            .groupBy { (it.segments.first() as DCQLClaimsPathPointerSegment.NameSegment).name }
            .map { it.key to ItemsRequestList(it.value.map { it.toSingleItemsRequest() }) }
            .takeIf { it.isNotEmpty() } ?: listOf()

    private fun RequestedAttributePaths.singleClaimsItems(): List<Pair<String, ItemsRequestList>> =
        filter { it.segments.all { it is DCQLClaimsPathPointerSegment.NameSegment } }
            .filter { it.segments.size == 1 }
            .map { it.toSingleItemsRequest() }
            .takeIf { it.isNotEmpty() }?.let {
                listOf(credentialScheme.isoNamespace!! to ItemsRequestList(it))
            } ?: listOf()

    fun effectiveRequestedAttributePaths(): RequestedAttributePaths =
        attributePaths ?: emptySet()

    fun effectiveRequestedOptionalAttributePaths(): RequestedAttributePaths =
        optionalAttributePaths ?: emptySet()

}

fun DCQLClaimsPathPointer.toIsoMdocClaimPath(
    scheme: CredentialScheme?,
): DCQLClaimsPathPointer {
    require(segments.all { it is DCQLClaimsPathPointerSegment.NameSegment }) {
        "ISO mdoc requested attribute paths must contain only name segments"
    }
    return when (segments.size) {
        1 -> DCQLClaimsPathPointer(
            scheme?.isoNamespace ?: "mdoc",
            (segments.first() as DCQLClaimsPathPointerSegment.NameSegment).name,
        )

        2 -> this
        else -> throw IllegalArgumentException(
            "ISO mdoc requested attribute paths must contain a claim name or a namespace and claim name"
        )
    }
}


fun DCQLClaimsPathPointer.toSingleItemsRequest(): SingleItemsRequest {
    require(segments.all { it is DCQLClaimsPathPointerSegment.NameSegment }) {
        "ISO mdoc requested attribute paths must contain only name segments"
    }
    require(segments.size <= 2) {
        "ISO mdoc requested attribute paths must contain at most 2 segments"
    }
    val claimName = (segments.last() as DCQLClaimsPathPointerSegment.NameSegment).name
    return SingleItemsRequest(
        dataElementIdentifier = claimName,
        intentToRetain = false
    )
}
