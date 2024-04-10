package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.data.dif.CredentialDefinition
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OID4VCI: Object that describes specifics of the Credential that the Credential Issuer supports issuance of.
 * This object contains a list of name/value pairs, where each name is a unique identifier of the supported Credential
 * being described. This identifier is used in the Credential Offer to communicate to the Wallet which Credential is
 * being offered.
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
     * OID4VCI: OPTIONAL. A JSON string identifying the scope value that this Credential Issuer supports for this
     * particular Credential. The value can be the same across multiple `credential_configurations_supported` objects.
     * The Authorization Server MUST be able to uniquely identify the Credential Issuer based on the `scope` value.
     * The Wallet can use this value in the Authorization Request. Scope values in this Credential Issuer metadata MAY
     * duplicate those in the `scopes_supported` parameter of the Authorization Server.
     */
    @SerialName("scope")
    val scope: String? = null,

    /**
     * OID4VCI: OPTIONAL. Array of case-sensitive strings that identify how the Credential is bound to the identifier of
     * the End-User who possesses the Credential as defined in Section 7.1. Support for keys in JWK format (RFC7517) is
     * indicated by the value `jwk`. Support for keys expressed as a COSE Key object (RFC8152) (for example, used in
     * ISO.18013-5) is indicated by the value `cose_key`. When Cryptographic Binding Method is a DID, valid values MUST
     * be a `did:` prefix followed by a method-name using a syntax as defined in Section 3.1 of [DID-Core], but without
     * a `:` and method-specific-id. For example, support for the DID method with a method-name "example" would be
     * represented by `did:example`.
     */
    @SerialName("cryptographic_binding_methods_supported")
    val supportedBindingMethods: Collection<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Array of case sensitive strings that identify the algorithms that the Issuer uses to sign the
     * issued Credential. Algorithm names used are determined by the Credential format and are defined in Appendix A.
     */
    @SerialName("credential_signing_alg_values_supported")
    val supportedSigningAlgorithms: Collection<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Object that describes specifics of the key proof(s) that the Credential Issuer supports.
     * This object contains a list of name/value pairs, where each name is a unique identifier of the supported
     * proof type(s).
     */
    @SerialName("proof_types_supported")
    val supportedProofTypes: Map<String, CredentialRequestProofSupported>? = null,

    /**
     * OID4VCI: W3C VC: REQUIRED.
     */
    @SerialName("credential_definition")
    val credentialDefinition: SupportedCredentialFormatDefinition? = null,

    /**
     * OID4VCI: IETF SD-JWT VC: REQUIRED. String designating the type of a Credential, as defined in
     * (I-D.ietf-oauth-sd-jwt-vc).
     */
    @SerialName("vct")
    val sdJwtVcType: String? = null,

    /**
     * OID4VCI:
     * ISO mDL: REQUIRED. String identifying the Credential type, as defined in (ISO.18013-5).
     */
    @SerialName("doctype")
    val docType: String? = null,

    // TODO For IETF SD-JWT VC this may be nested differently ... see OID4VCI Draft 13.
    /**
     * OID4VCI:
     * ISO mDL: OPTIONAL. Object containing a list of name/value pairs, where the name is a certain namespace as
     * defined in (ISO.18013-5) (or any profile of it), and the value is an object. This object also contains a list
     * of name/value pairs, where the name is a claim name value that is defined in the respective namespace and is
     * offered in the Credential.
     */
    @SerialName("claims")
    val claims: Map<String, Map<String, RequestedCredentialClaimSpecification>>? = null,

    /**
     * OID4VCI:
     * ISO mDL: OPTIONAL.
     * W3C VC: OPTIONAL.
     *
     * An array of `claims.display.name` values that lists them in the order they should be displayed by the Wallet.
     */
    @SerialName("order")
    val order: Collection<String>? = null,

    /**
     * OID4VCI: OPTIONAL. Array of objects, where each object contains the display properties of the supported
     * Credential for a certain language. Below is a non-exhaustive list of parameters that MAY be included.
     */
    @SerialName("display")
    val display: Collection<DisplayProperties>? = null,
)