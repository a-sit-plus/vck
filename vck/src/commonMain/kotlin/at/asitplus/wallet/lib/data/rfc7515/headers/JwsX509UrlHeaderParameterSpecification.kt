package at.asitplus.wallet.lib.data.rfc7515.headers

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName

/**
 * 4.1.5.  "x5u" (X.509 URL) Header Parameter
 *
 *    The "x5u" (X.509 URL) Header Parameter is a URI [RFC3986] that refers
 *    to a resource for the X.509 public key certificate or certificate
 *    chain [RFC5280] corresponding to the key used to digitally sign the
 *    JWS.  The identified resource MUST provide a representation of the
 *    certificate or certificate chain that conforms to RFC 5280 [RFC5280]
 *    in PEM-encoded form, with each certificate delimited as specified in
 *    Section 6.1 of RFC 4945 [RFC4945].  The certificate containing the
 *    public key corresponding to the key used to digitally sign the JWS
 *    MUST be the first certificate.  This MAY be followed by additional
 *    certificates, with each subsequent certificate being the one used to
 *    certify the previous one.  The protocol used to acquire the resource
 *    MUST provide integrity protection; an HTTP GET request to retrieve
 *    the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of
 *    the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
 *    Also, see Section 8 on TLS requirements.  Use of this Header
 *    Parameter is OPTIONAL.
 */
object JwsX509UrlHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "x5u"

    interface ClaimProvider {
        @SerialName(NAME)
        val x5u: UniformResourceIdentifier?
    }

    val JwsHeaderParameterSpecification.Companion.x5u: JwsX509UrlHeaderParameterSpecification
        get() = JwsX509UrlHeaderParameterSpecification
}
