package at.asitplus.wallet.lib.data.rfc7519.jwe.headers

import at.asitplus.wallet.lib.data.rfc7516.jwe.headers.JweHeaderParameterSpecification
import kotlinx.serialization.SerialName

/**
 * 4.1.2.  "sub" (Subject) Claim
 *
 *    The "sub" (subject) claim identifies the principal that is the
 *    subject of the JWT.  The claims in a JWT are normally statements
 *    about the subject.  The subject value MUST either be scoped to be
 *    locally unique in the context of the issuer or be globally unique.
 *    The processing of this claim is generally application specific.  The
 *    "sub" value is a case-sensitive string containing a StringOrURI
 *    value.  Use of this claim is OPTIONAL.
 *
 *    Section 10.4.1 of this specification registers the "iss" (issuer),
 *    "sub" (subject), and "aud" (audience) Header Parameter names for the
 *    purpose of providing unencrypted replicas of these claims in
 *    encrypted JWTs for applications that need them.  Other specifications
 *    MAY similarly register other names that are registered Claim Names as
 *    Header Parameter names, as needed.
 */
data object JweSubjectHeaderParameterSpecification : JweHeaderParameterSpecification {
    const val NAME = "sub"

    interface ParameterProvider {
        @SerialName(NAME)
        val sub: String?
    }

    val JweHeaderParameterSpecification.Companion.sub: JweSubjectHeaderParameterSpecification
        get() = JweSubjectHeaderParameterSpecification
}