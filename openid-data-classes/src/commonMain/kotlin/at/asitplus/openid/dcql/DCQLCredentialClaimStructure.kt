package at.asitplus.openid.dcql

import kotlinx.serialization.json.JsonElement
import kotlin.jvm.JvmInline

sealed interface DCQLCredentialClaimStructure {
    @JvmInline
    value class JsonBasedStructure(
        val jsonElement: JsonElement,
    ) : DCQLCredentialClaimStructure

    /**
     * The data elements of an ISO mdoc by namespace and data element identifier. To match the `values` of a claims
     * query, a value has to be the JSON value of the data element, converted from CBOR as OpenID4VP 1.0, 6.3 requires
     * (RFC 8949, 6.1), e.g. the string of a full-date. Kotlin strings, booleans and integers are accepted as they are;
     * values of other types are present, but do not match `values`.
     */
    @JvmInline
    value class IsoMdocStructure(
        val namespaceClaimValueMap: Map<String, Map<String, Any>>,
    ) : DCQLCredentialClaimStructure
}