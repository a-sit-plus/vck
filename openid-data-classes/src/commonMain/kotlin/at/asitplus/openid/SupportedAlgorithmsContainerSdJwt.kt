package at.asitplus.openid

import at.asitplus.signum.indispensable.josef.JsonWebAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class SupportedAlgorithmsContainerSdJwt(
    /**
     * OID4VP: OPTIONAL. A non-empty array containing fully-specified identifiers of cryptographic algorithms
     * (as defined in
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13))
     * supported for an Issuer-signed JWT of an SD-JWT.
     */
    @SerialName("sd-jwt_alg_values")
    val sdJwtAlgorithmStrings: Set<String>? = null,

    /**
     * OID4VP: OPTIONAL. A non-empty array containing fully-specified identifiers of cryptographic algorithms
     * (as defined in
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13))
     * supported for a Key Binding JWT (KB-JWT)
     */
    @SerialName("kb-jwt_alg_values")
    val kbJwtAlgorithmStrings: Set<String>? = null,
) {
    /**
     * OID4VP: OPTIONAL. A non-empty array containing fully-specified identifiers of cryptographic algorithms
     * (as defined in
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13))
     * supported for an Issuer-signed JWT of an SD-JWT.
     */
    @Transient
    val sdJwtAlgorithms: Set<JwsAlgorithm>? = sdJwtAlgorithmStrings
        ?.mapNotNull { s -> JwsAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()

    /**
     * OID4VP: OPTIONAL. A non-empty array containing fully-specified identifiers of cryptographic algorithms
     * (as defined in
     * [I-D.ietf-jose-fully-specified-algorithms](https://datatracker.ietf.org/doc/html/draft-ietf-jose-fully-specified-algorithms-13))
     * supported for a Key Binding JWT (KB-JWT)
     */
    @Transient
    val kbJwtAlgorithms: Set<JwsAlgorithm>? = kbJwtAlgorithmStrings
        ?.mapNotNull { s -> JwsAlgorithm.entries.firstOrNull { it.identifier == s } }?.toSet()


}