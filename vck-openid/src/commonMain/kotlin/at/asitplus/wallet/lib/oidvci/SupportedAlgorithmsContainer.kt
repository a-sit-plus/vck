package at.asitplus.wallet.lib.oidvci

import at.asitplus.crypto.datatypes.jws.JsonWebAlgorithm
import at.asitplus.crypto.datatypes.jws.JweAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class SupportedAlgorithmsContainer(
    /**
     * OID4VP: An object where the value is an array of case sensitive strings that identify the cryptographic suites
     * that are supported. Parties will need to agree upon the meanings of the values used, which may be
     * context-specific, e.g. `EdDSA` and `ES256`.
     */
    @SerialName("alg_values_supported")
    val supportedAlgorithms: Set<JsonWebAlgorithm>,

    /**
     * OID4VCI: REQUIRED. Array containing a list of the JWE (RFC7516) encryption algorithms (enc values) (RFC7518)
     * supported by the Credential and Batch Credential Endpoint to encode the Credential or Batch Credential Response
     * in a JWT (RFC7519).
     */
    @SerialName("enc_values_supported")
    val supportedEncryptionAlgorithms: Set<JweAlgorithm>? = null,

    /**
     * OID4VCI: REQUIRED. Boolean value specifying whether the Credential Issuer requires the additional encryption
     * on top of TLS for the Credential Response. If the value is `true`, the Credential Issuer requires encryption for
     * every Credential Response and therefore the Wallet MUST provide encryption keys in the Credential Request.
     * If the value is `false`, the Wallet MAY choose whether it provides encryption keys or not.
     */
    @SerialName("encryption_required")
    val encryptionRequired: Boolean? = null,
)