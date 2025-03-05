package at.asitplus.wallet.lib.oidvci

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.JwsService
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * To be set as header `DPoP` in making request to [url],
 * see [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
 */
suspend fun JwsService.buildDPoPHeader(
    url: String,
    httpMethod: String = "POST",
    accessToken: String? = null,
) = createSignedJwsAddingParams(
    header = JwsHeader(
        algorithm = algorithm,
        type = JwsContentTypeConstants.DPOP_JWT
    ),
    payload = JsonWebToken(
        jwtId = Random.Default.nextBytes(12).encodeToString(Base64UrlStrict),
        httpMethod = httpMethod,
        httpTargetUrl = url,
        accessTokenHash = accessToken?.encodeToByteArray()?.sha256()?.encodeToString(Base64UrlStrict),
        issuedAt = Clock.System.now(),
    ),
    serializer = JsonWebToken.Companion.serializer(),
    addKeyId = false,
    addJsonWebKey = true,
    addX5c = false,
).getOrThrow().serialize()

/**
 * Client attestation JWT, issued by the backend service to a client, which can be sent to an OAuth2 Authorization
 * Server if needed, e.g. as HTTP header `OAuth-Client-Attestation`, see
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *
 * @param clientId OAuth 2.0 client ID of the wallet
 * @param issuer a unique identifier for the entity that issued the JWT
 * @param clientKey key to be attested, i.e. included in a [at.asitplus.signum.indispensable.josef.ConfirmationClaim]
 * @param walletName human-readable name of the Wallet
 * @param walletLink URL for further information about the Wallet Provider
 * @param lifetime validity period of the assertion (minus the [clockSkew])
 * @param clockSkew duration to subtract from [Clock.System.now] when setting the creation timestamp
 */
// TODO Use this in an test, also HAIP requires the credential issuer to require client attestation!
suspend fun JwsService.buildClientAttestationJwt(
    clientId: String,
    issuer: String,
    clientKey: JsonWebKey,
    walletName: String? = null,
    walletLink: String? = null,
    lifetime: Duration = 60.minutes,
    clockSkew: Duration = 5.minutes,
) = createSignedJwsAddingParams(
    header = JwsHeader(
        algorithm = algorithm,
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_JWT
    ),
    payload = JsonWebToken(
        issuer = issuer,
        subject = clientId,
        issuedAt = Clock.System.now() - clockSkew,
        expiration = Clock.System.now() - clockSkew + lifetime,
        walletName = walletName,
        walletLink = walletLink,
        confirmationClaim = ConfirmationClaim(
            jsonWebKey = clientKey,
        )
    ),
    serializer = JsonWebToken.Companion.serializer(),
    addKeyId = false,
    addJsonWebKey = false,
    addX5c = false,
).getOrThrow()

/**
 * Client attestation PoP JWT, issued by the client, which can be sent to an OAuth2 Authorization Server if needed,
 * e.g. as HTTP header `OAuth-Client-Attestation-PoP`, see
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-04.html)
 *
 * @param clientId OAuth 2.0 client ID of the wallet
 * @param audience The RFC8414 issuer identifier URL of the authorization server MUST be used
 * @param nonce optionally provided from the authorization server
 * @param lifetime validity period of the assertion (minus the [clockSkew])
 * @param clockSkew duration to subtract from [Clock.System.now] when setting the creation timestamp
 */
suspend fun JwsService.buildClientAttestationPoPJwt(
    clientId: String,
    audience: String,
    nonce: String? = null,
    lifetime: Duration = 10.minutes,
    clockSkew: Duration = 5.minutes,
) = createSignedJwsAddingParams(
    header = JwsHeader(
        algorithm = algorithm,
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT
    ),
    payload = JsonWebToken(
        issuer = clientId,
        audience = audience,
        jwtId = Random.Default.nextBytes(12).encodeToString(Base64UrlStrict),
        nonce = nonce,
        issuedAt = Clock.System.now() - clockSkew,
        expiration = Clock.System.now() - clockSkew + lifetime,
    ),
    serializer = JsonWebToken.Companion.serializer(),
    addKeyId = false,
    addJsonWebKey = false,
    addX5c = false,
).getOrThrow()