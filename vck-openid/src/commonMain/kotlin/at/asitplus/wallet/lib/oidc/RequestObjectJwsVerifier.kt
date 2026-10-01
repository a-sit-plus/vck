package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompactTyped

@Deprecated("Request objects are verified in `AuthorizationRequestValidator` with `RelyingPartyTrust`")
fun interface RequestObjectJwsVerifier {
    suspend operator fun invoke(jws: JwsCompactTyped<RequestParameters>): Boolean
}