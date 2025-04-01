package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.JwsSigned

/**
 * Implementations need to verify the passed [at.asitplus.signum.indispensable.josef.JwsSigned] and return its result
 */
fun interface RequestObjectJwsVerifier {
    suspend operator fun invoke(jws: JwsSigned<RequestParameters>): Boolean
}