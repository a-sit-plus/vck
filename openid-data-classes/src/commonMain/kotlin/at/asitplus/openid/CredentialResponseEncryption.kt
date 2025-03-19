package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialResponseEncryption(
    /**
     * OID4VCI: REQUIRED. Object containing a single public key as a JWK used for encrypting the Credential Response.
     */
    @SerialName("jwk")
    val jsonWebKey: JsonWebKey,

    /**
     * OID4VCI: REQUIRED. JWE (RFC7516) `alg` algorithm (RFC7518) for encrypting Credential Responses.
     */
    @SerialName("alg")
    val jweAlgorithm: JweAlgorithm,

    /**
     * OID4VCI: REQUIRED. JWE (RFC7516) `enc` algorithm (RFC7518) for encrypting Credential Responses.
     */
    @SerialName("enc")
    val jweEncryptionString: String,
) {
    val jweEncryption: JweEncryption? =
        JweEncryption.entries.firstOrNull { it.text == jweEncryptionString }
}