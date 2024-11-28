package at.asitplus.wallet.lib.data.rfc7515.headers

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName

/**
 * 4.1.2.  "jku" (JWK Set URL) Header Parameter
 *
 *    The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
 *    refers to a resource for a set of JSON-encoded public keys, one of
 *    which corresponds to the key used to digitally sign the JWS.  The
 *    keys MUST be encoded as a JWK Set [JWK].  The protocol used to
 *    acquire the resource MUST provide integrity protection; an HTTP GET
 *    request to retrieve the JWK Set MUST use Transport Layer Security
 *    (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be
 *    validated, as per Section 6 of RFC 6125 [RFC6125].  Also, see
 *    Section 8 on TLS requirements.  Use of this Header Parameter is
 *    OPTIONAL.
 */
object JwsJsonWebKeySetUrlHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "jku"

    interface ClaimProvider {
        @SerialName(NAME)
        val jku: UniformResourceIdentifier?
    }

    val JwsHeaderParameterSpecification.Companion.alg: JwsJsonWebKeySetUrlHeaderParameterSpecification
        get() = JwsJsonWebKeySetUrlHeaderParameterSpecification
}
