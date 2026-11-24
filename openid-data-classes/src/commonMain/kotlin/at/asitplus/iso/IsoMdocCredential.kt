package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.jvm.JvmStatic

/**
 * An ISO mdoc as the rules of a [DeviceRequest] see it (ISO/IEC DIS 18013-5:2026, 10.2), the counterpart of
 * [at.asitplus.openid.dcql.DCQLCredential] for DCQL: a stored credential of a holder, or a document of a response.
 *
 * Describes an mdoc like [at.asitplus.openid.dcql.DCQLIsoMdocCredential] does for DCQL, but keeps the
 * [IssuerSignedItem]s with their values instead of a JSON claim structure, and the authority key identifiers as the
 * `issuerIdentifiers` of a document request compare them.
 */
data class IsoMdocCredential(
    /** The docType of the mdoc. */
    val docType: String,
    /**
     * The issuer-signed items of the mdoc, by their name space and data element identifier, as an [IssuerSignedItem]
     * carries no name space. Only issuer-signed data elements answer a document request.
     */
    val issuerSignedItems: Map<ElementReference, IssuerSignedItem>,
    /**
     * The key identifiers of the authority key identifier extensions of the certificates in the `x5chain` of the
     * `IssuerAuth` of the mdoc, computed by the caller, which [ItemsRequest.match] compares with the requested
     * `issuerIdentifiers` (ISO/IEC DIS 18013-5:2026, 10.2.4).
     */
    val authorityKeyIdentifiers: List<ByteArray>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IsoMdocCredential) return false

        if (docType != other.docType) return false
        if (issuerSignedItems != other.issuerSignedItems) return false
        if (authorityKeyIdentifiers.size != other.authorityKeyIdentifiers.size) return false
        if (!authorityKeyIdentifiers.zip(other.authorityKeyIdentifiers).all { (a, b) -> a.contentEquals(b) })
            return false

        return true
    }

    override fun hashCode(): Int {
        var result = docType.hashCode()
        result = 31 * result + issuerSignedItems.hashCode()
        result = 31 * result + authorityKeyIdentifiers.fold(1) { acc, it -> 31 * acc + it.contentHashCode() }
        return result
    }

    override fun toString(): String = "IsoMdocCredential(docType='$docType'," +
            " issuerSignedItems=$issuerSignedItems," +
            " authorityKeyIdentifiers=${authorityKeyIdentifiers.map { it.encodeToString(Base16Strict) }})"

    companion object {
        /**
         * The mdoc [issuerSigned] of [docType], with its issuer-signed items by name space and data element
         * identifier, see [issuerSignedItems], and the [authorityKeyIdentifiers] of the `x5chain` of its `IssuerAuth`.
         */
        @JvmStatic
        fun of(
            docType: String,
            issuerSigned: IssuerSigned,
            authorityKeyIdentifiers: List<ByteArray>,
        ) = IsoMdocCredential(
            docType = docType,
            issuerSignedItems = issuerSigned.namespaces.orEmpty().flatMap { (namespace, items) ->
                items.entries.map { ElementReference(namespace, it.value.elementIdentifier) to it.value }
            }.toMap(),
            authorityKeyIdentifiers = authorityKeyIdentifiers,
        )
    }
}
