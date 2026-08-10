package at.asitplus.wallet.lib.oauth2

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompact
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsTyped
import io.ktor.http.*
import kotlin.jvm.JvmOverloads

/** Holds information about the HTTP request the client has made, to validate client authentication. */
data class RequestInfo @JvmOverloads constructor(
    /** URL that has been used to send this request. */
    val url: String,
    /** HTTP method that the client has used. */
    val method: HttpMethod,
    /** Headers as received from the client. */
    val headers: Headers? = null,
) {

    // To be made internal after 8.0.0
    @Deprecated("Use main constructor taking in all HTTP headers")
    constructor(
        url: String,
        method: HttpMethod,
        dpop: JwsCompactTyped<JsonWebToken>? = null,
        clientAttestation: JwsCompactTyped<JsonWebToken>? = null,
        clientAttestationPop: JwsCompactTyped<JsonWebToken>? = null,
    ) : this(
        url = url,
        method = method,
        headers = headers {
            dpop?.let { set(HttpHeaders.DPoP, dpop.toString()) }
            clientAttestation?.let { set(HttpHeaders.OAuthClientAttestation, clientAttestation.toString()) }
            clientAttestationPop?.let { set(HttpHeaders.OAuthClientAttestationPop, clientAttestationPop.toString()) }
        }
    )

    /** Value of the header `DPoP` (RFC 9449). The value of the header is a JSON Web Token (JWT) */
    val dpop: JwsCompactTyped<JsonWebToken>?
        get() = headers.parseJwt(HttpHeaders.DPoP)

    /**
     * Value of the header `OAuth-Client-Attestation` (OAuth 2.0 Attestation-Based Client Authentication).
     * A JWT that conforms to the structure and syntax as defined in Section 4.2
     */
    val clientAttestation: JwsCompactTyped<JsonWebToken>?
        get() = headers.parseJwt(HttpHeaders.OAuthClientAttestation)

    /**
     * Value of the header `OAuth-Client-Attestation-PoP` (OAuth 2.0 Attestation-Based Client Authentication).
     * A JWT that adheres to the structure and syntax as defined in Section 4.3
     */
    val clientAttestationPop: JwsCompactTyped<JsonWebToken>?
        get() = headers.parseJwt(HttpHeaders.OAuthClientAttestationPop)

    private fun Headers?.parseJwt(headerName: String): JwsTyped<JwsCompact, JsonWebToken>? =
        catchingUnwrapped {
            this?.get(headerName)
                ?.takeIf { it.isNotEmpty() }
                ?.let { JwsCompactTyped<JsonWebToken>(it) }
        }.getOrNull()

}


val HttpHeaders.OAuthClientAttestation: String
    get() = "OAuth-Client-Attestation"

val HttpHeaders.OAuthClientAttestationPop: String
    get() = "OAuth-Client-Attestation-PoP"

val HttpHeaders.DPoP: String
    get() = "DPoP"

val HttpHeaders.DPoPNonce: String
    get() = "DPoP-Nonce"
