package at.asitplus.wallet.lib.data.rfc7515.headers

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 4.1.8.  "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
 *         Parameter
 *
 *    The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
 *    Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
 *    of the DER encoding of the X.509 certificate [RFC5280] corresponding
 *    to the key used to digitally sign the JWS.  Note that certificate
 *    thumbprints are also sometimes known as certificate fingerprints.
 *    Use of this Header Parameter is OPTIONAL.
 */
object JwsX509CertificateSha256ThumbprintHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "x5t#S256"

    interface ClaimProvider {
        @Serializable(with = ByteArrayBase64UrlSerializer::class)
        @SerialName(NAME)
        val x5tS256: ByteArray?
    }

    val JwsHeaderParameterSpecification.Companion.x5tS256: JwsX509CertificateSha256ThumbprintHeaderParameterSpecification
        get() = JwsX509CertificateSha256ThumbprintHeaderParameterSpecification
}