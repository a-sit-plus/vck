package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: A JSON array containing a list of JSON objects, each of them representing metadata about a
 * separate credential type that the Credential Issuer can issue. The JSON objects in the array MUST conform to the
 * structure of the Section 10.2.3.1.
 */
@Serializable
data class SupportedCredentialFormat(
    /**
     * OID4VCI: REQUIRED. A JSON string identifying the format of this credential, e.g. `jwt_vc_json` or `ldp_vc`.
     * Depending on the format value, the object contains further elements defining the type and (optionally) particular
     * claims the credential MAY contain, and information how to display the credential.
     */
    @SerialName("format")
    val format: CredentialFormatEnum,

    /**
     * OID4VCI: OPTIONAL. A JSON string identifying the respective object. The value MUST be unique across all
     * `credentials_supported` entries in the Credential Issuer Metadata.
     */
    @SerialName("id")
    val id: String? = null,

    /**
     * OID4VCI:
     * ISO mDL: N/A.
     * W3C Verifiable Credentials: OPTIONAL.
     *
     * JSON array designating the types a certain credential type supports according to (VC_DATA),
     * Section 4.3.
     * e.g. `VerifiableCredential`, `UniversityDegreeCredential`
     */
    @SerialName("types")
    val types: Array<String>,

    /**
     * OID4VCI:
     * ISO mDL: N/A.
     * W3C Verifiable Credentials: OPTIONAL.
     *
     * A JSON object containing a list of key value pairs, where the key identifies the claim offered
     * in the Credential. The value MAY be a dictionary, which allows to represent the full (potentially deeply nested)
     * structure of the verifiable credential to be issued. The value is a JSON object detailing the specifics about the
     * support for the claim.
     */
    @SerialName("credentialSubject")
    val credentialSubject: Map<String, CredentialSubjectMetadataSingle>? = null,

    /**
     * OID4VCI:
     * ISO mDL: OPTIONAL.
     * W3C Verifiable Credentials: N/A.
     *
     * JSON string identifying the credential type.
     */
    @SerialName("doctype")
    val docType: String? = null,

    /**
     * OID4VCI:
     * ISO mDL: OPTIONAL.
     * W3C Verifiable Credentials: N/A.
     *
     * A JSON object containing a list of key value pairs,
     * where the key is a certain namespace as defined in [ISO.18013-5] (or any profile of it),
     * and the value is a JSON object. This object also contains a list of key value pairs,
     * where the key is a claim that is defined in the respective namespace and is offered in the Credential.
     */
    @SerialName("claims")
    val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

    /**
     * OID4VCI:
     * ISO mDL: OPTIONAL.
     * W3C Verifiable Credentials: OPTIONAL.
     *
     * An array of claims.display.name values that lists them in the order they should be displayed by the Wallet.
     */
    @SerialName("order")
    val order: Array<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Array of case-sensitive strings that identify how the Credential is bound to the identifier of
     * the End-User who possesses the Credential as defined in Section 7.1. Support for keys in JWK format (RFC7517) is
     * indicated by the value `jwk`. Support for keys expressed as a COSE Key object (RFC8152) (for example, used in
     * ISO.18013-5) is indicated by the value `cose_key`. When Cryptographic Binding Method is a DID, valid values MUST
     * be a `did:` prefix followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core], but without
     * a `:` and method-specific-id. For example, support for the DID method with a method-name "example" would be
     * represented by `did:example`. Support for all DID methods listed in Section 13 of (DID_Specification_Registries)
     * is indicated by sending a DID without any method-name.
     */
    @SerialName("cryptographic_binding_methods_supported")
    val supportedBindingMethods: Array<String>,

    /**
     * OID4VCI: OPTIONAL. Array of case-sensitive strings that identify the cryptographic suites that are supported for
     * the `cryptographic_binding_methods_supported`. Cryptosuites for Credentials in `jwt_vc` format should use
     * algorithm names defined in IANA JOSE Algorithms Registry. Cryptosuites for Credentials in `ldp_vc` format should
     * use signature suites names defined in Linked Data Cryptographic Suite Registry.
     */
    @SerialName("cryptographic_suites_supported")
    val supportedCryptographicSuites: Array<String>,

    //    // TODO
    //    /**
    //     * OID4VCI:
    //     * OPTIONAL. An array of objects, where each object contains the display properties of the supported credential for a certain language.
    //     * Note that the display name of the supported credential is obtained from display.name and individual claim names from claims.display.name values.
    //     */
    //    @SerialName("display")
    //    val display: Array<>? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as SupportedCredentialFormat

        if (format != other.format) return false
        if (id != other.id) return false
        if (!types.contentEquals(other.types)) return false
        if (credentialSubject != other.credentialSubject) return false
        if (docType != other.docType) return false
        if (claims != other.claims) return false
        if (order != null) {
            if (other.order == null) return false
            if (!order.contentEquals(other.order)) return false
        } else if (other.order != null) return false
        if (!supportedBindingMethods.contentEquals(other.supportedBindingMethods)) return false
        return supportedCryptographicSuites.contentEquals(other.supportedCryptographicSuites)
    }

    override fun hashCode(): Int {
        var result = format.hashCode()
        result = 31 * result + (id?.hashCode() ?: 0)
        result = 31 * result + types.contentHashCode()
        result = 31 * result + (credentialSubject?.hashCode() ?: 0)
        result = 31 * result + (docType?.hashCode() ?: 0)
        result = 31 * result + (claims?.hashCode() ?: 0)
        result = 31 * result + (order?.contentHashCode() ?: 0)
        result = 31 * result + supportedBindingMethods.contentHashCode()
        result = 31 * result + supportedCryptographicSuites.contentHashCode()
        return result
    }
}