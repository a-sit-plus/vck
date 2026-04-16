package at.asitplus.wallet.lib.oidc

import at.asitplus.signum.indispensable.josef.JWS

/**
 * Implementations need to verify the passed [at.asitplus.signum.indispensable.josef.JWS] and return its result
 */
fun interface RequestObjectJwsVerifier {
    suspend operator fun invoke(jws: JWS): Boolean
}