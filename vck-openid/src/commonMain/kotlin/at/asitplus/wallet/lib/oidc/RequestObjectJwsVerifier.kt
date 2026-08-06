package at.asitplus.wallet.lib.oidc

import at.asitplus.openid.RequestParameters
import at.asitplus.signum.indispensable.josef.JwsCompactTyped

@Deprecated(
    "Superseded by RelyingPartyTrust, evaluated per client identifier scheme in AuthorizationRequestValidator: " +
            "this cannot express multi-signature or DC API requests, and loses the reason for a rejection."
)
fun interface RequestObjectJwsVerifier {
    suspend operator fun invoke(jws: JwsCompactTyped<RequestParameters>): Boolean
}