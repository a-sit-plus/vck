package at.asitplus.wallet.lib.data.rfc7515.headers

import at.asitplus.signum.indispensable.josef.io.JwsCertificateSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 4.1.6.  "x5c" (X.509 Certificate Chain) Header Parameter
 *
 *    The "x5c" (X.509 certificate chain) Header Parameter contains the
 *    X.509 public key certificate or certificate chain [RFC5280]
 *    corresponding to the key used to digitally sign the JWS.  The
 *    certificate or certificate chain is represented as a JSON array of
 *    certificate value strings.  Each string in the array is a
 *    base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
 *    [ITU.X690.2008] PKIX certificate value.  The certificate containing
 *    the public key corresponding to the key used to digitally sign the
 *    JWS MUST be the first certificate.  This MAY be followed by
 *    additional certificates, with each subsequent certificate being the
 *    one used to certify the previous one.  The recipient MUST validate
 *    the certificate chain according to RFC 5280 [RFC5280] and consider
 *    the certificate or certificate chain to be invalid if any validation
 *    failure occurs.  Use of this Header Parameter is OPTIONAL.
 */
object JwsX509CertificateChainHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "x5c"

    interface ClaimProvider {
        @Serializable(with = JwsCertificateSerializer::class)
        @SerialName(NAME)
        val x5c: List<X509Certificate>?
    }

    val JwsHeaderParameterSpecification.Companion.x5c: JwsX509CertificateChainHeaderParameterSpecification
        get() = JwsX509CertificateChainHeaderParameterSpecification
}
