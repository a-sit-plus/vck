package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class SupportedAlgorithmsContainer(
    /**
     * OID4VP: An object where the value is an array of case sensitive strings that identify the cryptographic suites
     * that are supported. Parties will need to agree upon the meanings of the values used, which may be
     * context-specific, e.g. `EdDSA` and `ES256`.
     */
    @SerialName("alg_values_supported")
    val supportedAlgorithmsStrings: Set<String>,

    /**
     * OID4VCI: REQUIRED. Array containing a list of the JWE (RFC7516) encryption algorithms (enc values) (RFC7518)
     * supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response
     * in a JWT (RFC7519).
     */
    @SerialName("enc_values_supported")
    val supportedEncryptionAlgorithmsStrings: Set<String>? = null,

    /**
     * OID4VCI: REQUIRED. Boolean value specifying whether the Credential Issuer requires the additional encryption
     * on top of TLS for the Credential Response. If the value is `true`, the Credential Issuer requires encryption for
     * every Credential Response and therefore the Wallet MUST provide encryption keys in the Credential Request.
     * If the value is `false`, the Wallet MAY choose whether it provides encryption keys or not.
     */
    @SerialName("encryption_required")
    val encryptionRequired: Boolean? = null,

    /**
     * OID4VCI: REQUIRED for [IssuerMetadata.credentialRequestEncryption].
     * A JSON Web Key Set, as defined in [RFC7591](https://datatracker.ietf.org/doc/html/rfc7591),
     * that contains one or more public keys, to be used by the Wallet as an input to a key agreement for encryption
     * of the Credential Request.
     * Each JWK in the set MUST have a kid (Key ID) parameter that uniquely identifies the key.
     */
    @SerialName("jwks")
    val jsonWebKeySet: JsonWebKeySet? = null,
) {

    /**
     * OID4VP: An object where the value is an array of case sensitive strings that identify the cryptographic suites
     * that are supported. Parties will need to agree upon the meanings of the values used, which may be
     * context-specific, e.g. `EdDSA` and `ES256`.
     */
    @Transient
    val supportedAlgorithms: Set<JsonWebAlgorithm> = supportedAlgorithmsStrings
        .mapNotNull { s -> JsonWebAlgorithm.entries.firstOrNull { it.identifier == s } }.toSet()

    /**
     * OID4VCI: REQUIRED. Array containing a list of the JWE (RFC7516) encryption algorithms (enc values) (RFC7518)
     * supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response
     * in a JWT (RFC7519).
     */
    @Transient
    val supportedEncryptionAlgorithms: Set<JweEncryption>? = supportedEncryptionAlgorithmsStrings
        ?.mapNotNull { s -> JweEncryption.entries.firstOrNull { it.identifier == s } }?.toSet()
}