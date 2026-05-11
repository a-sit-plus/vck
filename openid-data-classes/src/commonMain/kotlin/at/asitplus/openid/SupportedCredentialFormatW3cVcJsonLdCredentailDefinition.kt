package at.asitplus.openid

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class SupportedCredentialFormatW3cVcJsonLdCredentailDefinition(
    /**
     * OID4VCI: @context: REQUIRED. Array as defined in [VC_DATA], Section 4.1.
     *
     * VC_DATA Section 4.1
     *     The value of the @context property MUST be an ordered set where the first item is a URI with the value
     *     https://www.w3.org/2018/credentials/v1. For reference, a copy of the base context is provided in Appendix
     *     B.1 Base Context. Subsequent items in the array MUST express context information and be composed of any
     *     combination of URIs or objects. It is RECOMMENDED that each URI in the @context be one which, if
     *     dereferenced, results in a document containing machine-readable information about the @context.
     */
    @SerialName(SerialNames.CONTEXT)
    val context: List<JsonElement>,
    /**
     * OID4VCI: type: REQUIRED. Array designating the types a certain credential type supports, according to [VC_DATA],
     * Section 4.3.
     *
     * VC_DATA Section 4.3
     *     The value of the type property MUST be, or map to (through interpretation of the @context property), one or
     *     more URIs. If more than one URI is provided, the URIs MUST be interpreted as an unordered set. Syntactic
     *     conveniences SHOULD be used to ease developer usage. Such conveniences might include JSON-LD terms. It is
     *     RECOMMENDED that each URI in the type be one which, if dereferenced, results in a document containing
     *     machine-readable information about the type.
     */
    @SerialName(SerialNames.TYPE)
    val type: Set<String>,
) {
    object SerialNames {
        const val TYPE = "type"
        const val CONTEXT = "@context"
    }
}