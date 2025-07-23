package at.asitplus.wallet.lib.data.rfc7519.jwt.claims

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrUri
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

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
 */
@Serializable
@JvmInline
value class JwtSubjectClaim(val stringOrUri: StringOrUri) {
    val string: String
        get() = stringOrUri.string

    val uri: UniformResourceIdentifier?
        get() = stringOrUri.uri

    val isUri: Boolean
        get() = stringOrUri.isUri

    companion object {
        operator fun invoke(string: String)  = JwtSubjectClaim(StringOrUri(string))
        operator fun invoke(uri: UniformResourceIdentifier)  = JwtSubjectClaim(uri.string)
    }

    data object Specification {
        const val CLAIM_NAME = "sub"
    }
}
