package at.asitplus.wallet.lib.data.rfc7515.headers

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 4.1.7.  "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
 *
 *    The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
 *    base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
 *    encoding of the X.509 certificate [RFC5280] corresponding to the key
 *    used to digitally sign the JWS.  Note that certificate thumbprints
 *    are also sometimes known as certificate fingerprints.  Use of this
 *    Header Parameter is OPTIONAL.
 */
object JwsX509CertificateSha1ThumbprintHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "x5t"

    interface ClaimProvider {
        @Serializable(with = ByteArrayBase64UrlSerializer::class)
        @SerialName(NAME)
        val x5t: ByteArray?
    }

    val JwsHeaderParameterSpecification.Companion.x5t: JwsX509CertificateSha1ThumbprintHeaderParameterSpecification
        get() = JwsX509CertificateSha1ThumbprintHeaderParameterSpecification
}