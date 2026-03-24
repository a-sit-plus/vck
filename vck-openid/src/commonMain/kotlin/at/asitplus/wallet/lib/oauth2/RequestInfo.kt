package at.asitplus.wallet.lib.oauth2

import io.ktor.http.*

//TODO? use [JwsCompactTyped<JsonWebToken>] directly for dpop, clientAttestation, clientAttestationPop?
/** Holds information about the HTTP request the client has made, to validate client authentication. */
data class RequestInfo(
    /** URL that has been used to send this request. */
    val url: String,
    /** HTTP method that the client has used. */
    val method: HttpMethod,

    /** Value of the header `DPoP` (RFC 9449). The value of the header is a JSON Web Token (JWT) */
    val dpop: String? = null,
    /**
     * Value of the header `OAuth-Client-Attestation` (OAuth 2.0 Attestation-Based Client Authentication).
     * A JWT that conforms to the structure and syntax as defined in Section 4.2
     */
    val clientAttestation: String? = null,
    /**
     * Value of the header `OAuth-Client-Attestation-PoP` (OAuth 2.0 Attestation-Based Client Authentication).
     * A JWT that adheres to the structure and syntax as defined in Section 4.3
     */
    val clientAttestationPop: String? = null,
)