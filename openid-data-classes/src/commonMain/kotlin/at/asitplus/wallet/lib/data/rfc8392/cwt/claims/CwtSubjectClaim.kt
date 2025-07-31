package at.asitplus.wallet.lib.data.rfc8392.cwt.claims

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrUri
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * source: https://www.rfc-editor.org/rfc/rfc8392
 *
 * 3.1.2.  sub (Subject) Claim
 *
 *    The "sub" (subject) claim has the same meaning and processing rules
 *    as the "sub" claim defined in Section 4.1.2 of [RFC7519], except that
 *    the value is a StringOrURI, as defined in Section 2 of this
 *    specification.  The Claim Key 2 is used to identify this claim.
 */
@Serializable
@JvmInline
value class CwtSubjectClaim(val value: StringOrUri) {
    val string: String
        get() = value.string

    val uri: UniformResourceIdentifier?
        get() = value.uri

    companion object {
        operator fun invoke(string: String) = CwtSubjectClaim(StringOrUri(string))
        operator fun invoke(uri: UniformResourceIdentifier) = CwtSubjectClaim(StringOrUri.Companion(uri))
    }

    data object Specification {
        const val CLAIM_NAME = "sub"
        const val CLAIM_KEY = 2L
    }
}