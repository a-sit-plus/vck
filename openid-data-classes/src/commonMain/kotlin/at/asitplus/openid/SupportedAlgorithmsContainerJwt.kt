package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class SupportedAlgorithmsContainerJwt(
    /**
     * OID4VP: OPTIONAL. A non-empty array containing identifiers of cryptographic algorithms supported for a
     * JWT-secured W3C Verifiable Credential or W3C Verifiable Presentation. If present, the `alg` JOSE header
     * (as defined in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) of the presented Verifiable Credential
     * or Verifiable Presentation MUST match one of the array values.
     */
    @SerialName("alg_values")
    val algorithmStrings: Set<String>,
) {

    /**
     * OID4VP: OPTIONAL. A non-empty array containing identifiers of cryptographic algorithms supported for a
     * JWT-secured W3C Verifiable Credential or W3C Verifiable Presentation. If present, the alg JOSE header
     * (as defined in [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)) of the presented Verifiable Credential
     * or Verifiable Presentation MUST match one of the array values.
     */
    @Transient
    val algorithms: Set<JsonWebAlgorithm> = algorithmStrings
        .mapNotNull { s -> JsonWebAlgorithm.entries.firstOrNull { it.identifier == s } }.toSet()
}