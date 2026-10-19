package at.asitplus.wallet.lib.oidvci

import at.asitplus.iso.sha256
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ClientStatus
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.SignJwtFun
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant

object BuildDPoPHeader {
    /**
     * To be set as header `DPoP` in making request to [url],
     * see [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449).
     *
     * @param signDpop function to sign the JWT
     * @param url target URL of the request
     * @param httpMethod HTTP method of the request (in upper casse according to RFC 9449)
     * @param accessToken access token to hash and include in the JWT
     * @param nonce nonce to include in the JWT
     * @param randomSource source of randomness for generating the JWT ID
     * @param issuedAt timestamp to use as the creation timestamp
     */
    suspend operator fun invoke(
        signDpop: SignJwtFun<JsonWebToken>,
        url: String,
        httpMethod: String = "POST",
        accessToken: String? = null,
        nonce: String? = null,
        randomSource: RandomSource = RandomSource.Secure,
        issuedAt: Instant = Clock.System.now().truncateToSeconds(),
    ): JwsCompactTyped<JsonWebToken> = signDpop(
        type = JwsContentTypeConstants.DPOP_JWT,
        payload = JsonWebToken(
            jwtId = randomSource.nextBytes(12).encodeToString(Base64UrlStrict),
            httpMethod = httpMethod,
            httpTargetUrl = url,
            accessTokenHash = accessToken?.encodeToByteArray()?.sha256()?.encodeToString(Base64UrlStrict),
            issuedAt = issuedAt,
            nonce = nonce,
        ),
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()
}

object BuildClientAttestationJwt {
    /**
     * Client attestation JWT, issued by the backend service to a client, which can be sent to an OAuth2 Authorization
     * Server if needed, e.g. as HTTP header `OAuth-Client-Attestation`, see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
     *
     * @param clientId OAuth 2.0 client ID of the wallet
     * @param clientKey key to be attested, i.e. included in a [ConfirmationClaim]
     * @param walletName identifier of the Wallet Solution.
     * @param walletVersion version of the Wallet Solution.
     * @param walletSolutionCertificationInformation certification information for the Wallet Solution.
     * @param clientStatus status information for the Wallet Instance Attestation.
     * @param walletLink URL for further information about the Wallet Solution.
     * @param lifetime validity period of the assertion
     * @param issuedAt timestamp to use as the creation timestamp
     */
    suspend operator fun invoke(
        signJwt: SignJwtFun<JsonWebToken>,
        clientId: String,
        clientKey: JsonWebKey,
        walletName: String = clientId,
        walletVersion: String = "unspecified",
        walletSolutionCertificationInformation: String = "unspecified",
        clientStatus: ClientStatus? = null,
        walletLink: String? = null,
        lifetime: Duration = 60.minutes,
        issuedAt: Instant = Clock.System.now().truncateToSeconds(),
    ): JwsCompactTyped<JsonWebToken> = signJwt(
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_JWT,
        payload = JsonWebToken(
            subject = clientId,
            issuedAt = issuedAt,
            expiration = issuedAt + lifetime.coerceAtMost(24.hours - 1.minutes),
            walletName = walletName,
            walletLink = walletLink,
            walletVersion = walletVersion,
            walletSolutionCertificationInformation = walletSolutionCertificationInformation,
            clientStatus = clientStatus,
            confirmationClaim = ConfirmationClaim(jsonWebKey = clientKey)
        ),
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()
}

object BuildClientAttestationPoPJwt {
    /**
     * Client attestation PoP JWT, issued by the client, which can be sent to an OAuth2 Authorization Server if needed,
     * e.g. as HTTP header `OAuth-Client-Attestation-PoP`, see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
     *
     * @param audience The RFC8414 issuer identifier URL of the authorization server or the resource server MUST be used
     * @param nonce optionally provided from the authorization server
     * @param issuedAt timestamp to use as the creation timestamp
     */
    suspend operator fun invoke(
        signJwt: SignJwtFun<JsonWebToken>,
        audience: String,
        nonce: String? = null,
        randomSource: RandomSource = RandomSource.Secure,
        issuedAt: Instant = Clock.System.now().truncateToSeconds(),
    ): JwsCompactTyped<JsonWebToken> = signJwt(
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
        payload = JsonWebToken(
            audience = audience,
            jwtId = randomSource.nextBytes(12).encodeToString(Base64UrlStrict),
            // Setting both fields here, this changed in draft 10 of OAuth 2.0 Attestation-Based Client Auth
            nonce = nonce,
            challenge = nonce,
            issuedAt = issuedAt,
        ).also {
            Napier.d("Building client attestation PoP JWT: $it")
        },
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()
}
