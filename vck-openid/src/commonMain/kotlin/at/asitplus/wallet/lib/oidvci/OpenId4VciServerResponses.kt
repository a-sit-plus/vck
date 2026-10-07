package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.PreparedHttpResponse
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.jsonHttpResponse
import at.asitplus.wallet.lib.oauth2.DPoPNonce
import at.asitplus.wallet.lib.oauth2.NO_STORE
import io.ktor.http.*

/**
 * Converts the result of the nonce endpoint to its response: status 200 with the nonce as JSON,
 * `Cache-Control: no-store`
 * ([OID4VCI 1.0 7.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.2)), and
 * the header `DPoP-Nonce`, if present ([RFC 9449 8.2](https://datatracker.ietf.org/doc/html/rfc9449#section-8.2)).
 */
fun OpenId4VciServer.Nonce.toHttpResponse(): PreparedHttpResponse = jsonHttpResponse(response) {
    append(HttpHeaders.CacheControl, NO_STORE)
    dpopNonce?.let { append(HttpHeaders.DPoPNonce, it) }
}

/**
 * Converts the result of the credential endpoint to its response: status 200 with the credential response as
 * `application/json`, or encrypted as `application/jwt`
 * ([OID4VCI 1.0 8.3](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3),
 * [10.](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10)), and
 * `Cache-Control: no-store`, as in every credential response example of OID4VCI 1.0, since it contains credentials.
 *
 * Convert errors with [at.asitplus.wallet.lib.oauth2.toResourceServerHttpResponse].
 */
fun OpenId4VciServer.CredentialResponse.toHttpResponse(): PreparedHttpResponse = when (this) {
    is OpenId4VciServer.CredentialResponse.Plain -> jsonHttpResponse(response) {
        append(HttpHeaders.CacheControl, NO_STORE)
    }

    is OpenId4VciServer.CredentialResponse.Encrypted -> PreparedHttpResponse(
        status = HttpStatusCode.OK,
        headers = headers {
            append(HttpHeaders.ContentType, MediaTypes.Application.JWT)
            append(HttpHeaders.CacheControl, NO_STORE)
        },
        body = response.serialize(),
    )
}

/**
 * Whether the `Accept` header [acceptHeader] asks for signed issuer metadata, i.e. lists `application/jwt`
 * explicitly, with a quality not below the one of `application/json` (or `application/*`, `*/*`).
 * Wildcards alone never select signed metadata, as unsigned metadata is the one every client understands
 * ([OID4VCI 1.0 12.2.2](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.2)).
 */
internal fun acceptsSignedMetadata(acceptHeader: String?): Boolean {
    val accepted = parseHeaderValue(acceptHeader).associate { it.value.trim().lowercase() to it.quality }
    val jwtQuality = accepted[MediaTypes.Application.JWT] ?: return false
    val jsonQuality = accepted[MediaTypes.Application.JSON]
        ?: accepted["application/*"]
        ?: accepted["*/*"]
        ?: 0.0
    return jwtQuality > 0.0 && jwtQuality >= jsonQuality
}
