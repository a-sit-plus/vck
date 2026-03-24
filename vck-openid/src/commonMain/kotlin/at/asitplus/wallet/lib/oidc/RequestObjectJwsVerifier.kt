package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.JwsCompactTyped
import at.asitplus.openid.RequestParameters

/**
 * Implementations need to verify the passed [at.asitplus.signum.indispensable.josef.JwsSigned] and return its result
 */
fun interface RequestObjectJwsVerifier {
    suspend operator fun invoke(jws: JwsCompactTyped<RequestParameters>): Boolean
}