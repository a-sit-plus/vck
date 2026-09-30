package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.Errors.USE_ATTESTATION_CHALLENGE
import at.asitplus.openid.OpenIdConstants.Errors.USE_DPOP_NONCE
import at.asitplus.wallet.lib.oidvci.OAuth2Error
import io.ktor.http.*

/**
 * Extracts the header `DPoP-Nonce` from the [headers] of an error response, if the authorization server responded
 * with the error `use_dpop_nonce`, or the resource server did so in the header `WWW-Authenticate`.
 */
fun OAuth2Error?.dpopNonce(headers: Headers): String? =
    authorizationServerProvidedNonce(headers) ?: resourceServerProvidedNonce(headers)

/**
 * Extracts the header `OAuth-Client-Attestation-Challenge` from the [headers] of an error response, if the error is
 * `use_attestation_challenge`.
 */
fun OAuth2Error?.attestationChallenge(headers: Headers): String? =
    authorizationServerProvidedAttestationChallenge(headers)

/** [RFC 9449 8.](https://datatracker.ietf.org/doc/html/rfc9449#name-authorization-server-provid) */
private fun OAuth2Error?.authorizationServerProvidedNonce(headers: Headers): String? =
    this?.error.takeIf { it == USE_DPOP_NONCE }?.let { headers[HttpHeaders.DPoPNonce] }

/** [RFC 9449 9.](https://datatracker.ietf.org/doc/html/rfc9449#section-9) */
private fun resourceServerProvidedNonce(headers: Headers): String? =
    headers.takeIf {
        headers.getAll(HttpHeaders.WWWAuthenticate)?.any { it.contains(USE_DPOP_NONCE) } == true
    }?.let { headers[HttpHeaders.DPoPNonce] }

/** [OA-ABCA 6.2](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html#challenge-in-response) */
private fun OAuth2Error?.authorizationServerProvidedAttestationChallenge(headers: Headers): String? =
    this?.error.takeIf { it == USE_ATTESTATION_CHALLENGE }
        ?.let { headers[HttpHeaders.OAuthClientAttestationChallenge] }
