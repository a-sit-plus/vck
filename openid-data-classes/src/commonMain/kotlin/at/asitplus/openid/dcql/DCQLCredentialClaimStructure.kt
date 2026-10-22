package at.asitplus.openid.dcql

import kotlinx.serialization.json.JsonElement
import kotlin.jvm.JvmInline

sealed interface DCQLCredentialClaimStructure {
    @JvmInline
    value class JsonBasedStructure(
        val jsonElement: JsonElement,
    ) : DCQLCredentialClaimStructure

    /**
     * The data elements of an ISO mdoc by namespace and data element identifier, as their JSON values: OpenID4VP 1.0,
     * 6.3 requires the CBOR value of a data element to be converted to JSON (RFC 8949, 6.1) before it is matched against
     * the `values` of a claims query, e.g. a full-date to its string. A data element without a JSON value, e.g. of a
     * type without a known encoding, is [kotlinx.serialization.json.JsonNull], so that it is present but does not match
     * `values`.
     */
    @JvmInline
    value class IsoMdocStructure(
        val namespaceClaimValueMap: Map<String, Map<String, JsonElement>>,
    ) : DCQLCredentialClaimStructure
}