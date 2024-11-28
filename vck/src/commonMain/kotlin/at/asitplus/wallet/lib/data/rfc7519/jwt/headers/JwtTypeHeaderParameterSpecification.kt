package at.asitplus.wallet.lib.data.rfc7519.jwt.headers

import at.asitplus.wallet.lib.data.rfc7519.jwt.JwtHeaderParameterSpecification
import kotlinx.serialization.SerialName

/**
 * 5.1.  "typ" (Type) Header Parameter
 *
 *    The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used
 *    by JWT applications to declare the media type [IANA.MediaTypes] of
 *    this complete JWT.  This is intended for use by the JWT application
 *    when values that are not JWTs could also be present in an application
 *    data structure that can contain a JWT object; the application can use
 *    this value to disambiguate among the different kinds of objects that
 *    might be present.  It will typically not be used by applications when
 *    it is already known that the object is a JWT.  This parameter is
 *    ignored by JWT implementations; any processing of this parameter is
 *    performed by the JWT application.  If present, it is RECOMMENDED that
 *    its value be "JWT" to indicate that this object is a JWT.  While
 *    media type names are not case sensitive, it is RECOMMENDED that "JWT"
 *    always be spelled using uppercase characters for compatibility with
 *    legacy implementations.  Use of this Header Parameter is OPTIONAL.
 */
data object JwtTypeHeaderParameterSpecification : JwtHeaderParameterSpecification {
    const val NAME = "typ"

    interface ParameterProvider {
        @SerialName(NAME)
        val typ: String?
    }

    val JwtHeaderParameterSpecification.Companion.typ: JwtTypeHeaderParameterSpecification
        get() = JwtTypeHeaderParameterSpecification
}
