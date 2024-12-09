package at.asitplus.wallet.lib.data.rfc7515.headers

import at.asitplus.signum.indispensable.josef.JsonWebKey
import kotlinx.serialization.SerialName

/**
 * 4.1.3.  "jwk" (JSON Web Key) Header Parameter
 *
 *    The "jwk" (JSON Web Key) Header Parameter is the public key that
 *    corresponds to the key used to digitally sign the JWS.  This key is
 *    represented as a JSON Web Key [JWK].  Use of this Header Parameter is
 *    OPTIONAL.
 */
object JwsJsonWebKeyHeaderParameterSpecification : JwsHeaderParameterSpecification {
    const val NAME = "jwk"

    interface ClaimProvider {
        @SerialName(NAME)
        val jwk: JsonWebKey?
    }

    val JwsHeaderParameterSpecification.Companion.jwk: JwsJsonWebKeyHeaderParameterSpecification
        get() = JwsJsonWebKeyHeaderParameterSpecification
}
