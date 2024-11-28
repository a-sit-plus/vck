package at.asitplus.wallet.lib.data.rfc7515.headers

import kotlinx.serialization.SerialName

/**
 * 4.1.11.  "crit" (Critical) Header Parameter
 *
 *    The "crit" (critical) Header Parameter indicates that extensions to
 *    this specification and/or [JWA] are being used that MUST be
 *    understood and processed.  Its value is an array listing the Header
 *    Parameter names present in the JOSE Header that use those extensions.
 *    If any of the listed extension Header Parameters are not understood
 *    and supported by the recipient, then the JWS is invalid.  Producers
 *    MUST NOT include Header Parameter names defined by this specification
 *    or [JWA] for use with JWS, duplicate names, or names that do not
 *    occur as Header Parameter names within the JOSE Header in the "crit"
 *    list.  Producers MUST NOT use the empty list "[]" as the "crit"
 *    value.  Recipients MAY consider the JWS to be invalid if the critical
 *    list contains any Header Parameter names defined by this
 *    specification or [JWA] for use with JWS or if any other constraints
 *    on its use are violated.  When used, this Header Parameter MUST be
 *    integrity protected; therefore, it MUST occur only within the JWS
 *    Protected Header.  Use of this Header Parameter is OPTIONAL.  This
 *    Header Parameter MUST be understood and processed by implementations.
 *
 *    An example use, along with a hypothetical "exp" (expiration time)
 *    field is:
 *
 *      {"alg":"ES256",
 *       "crit":["exp"],
 *       "exp":1363284000
 *      }
 */
object JwsCriticalHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "crit"

    interface ClaimProvider {
        @SerialName(NAME)
        val crit: List<String>
    }

    val JwsHeaderParameterSpecification.Companion.crit: JwsCriticalHeaderParameterSpecification
        get() = JwsCriticalHeaderParameterSpecification
}

