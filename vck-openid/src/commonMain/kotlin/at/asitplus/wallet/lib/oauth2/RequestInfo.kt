package at.asitplus.wallet.lib.oauth2

import io.ktor.http.HttpMethod

/** Holds information about the HTTP request the client has made, to validate client authentication. */
data class RequestInfo(
    /** URL that has been used to send this request. */
    val url: String,
    /** HTTP method that the client has used. */
    val method: HttpMethod,
    /** Value of the header `DPoP` (RFC 9449). */
    val dpop: String? = null,
    /** Value of the header `OAuth-Client-Attestation` (OAuth 2.0 Attestation-Based Client Authentication). */
    val clientAttestation: String? = null,
    /** Value of the header `OAuth-Client-Attestation-PoP` (OAuth 2.0 Attestation-Based Client Authentication). */
    val clientAttestationPop: String? = null,
)