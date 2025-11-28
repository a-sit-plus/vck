package at.asitplus.wallet.lib.oidvci

import at.asitplus.iso.sha256
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.ConfirmationClaim
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.wallet.lib.agent.RandomSource
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.SignJwtFun
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

object BuildDPoPHeader {
    /**
     * To be set as header `DPoP` in making request to [url],
     * see [RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
     */
    suspend operator fun invoke(
        signDpop: SignJwtFun<JsonWebToken>,
        url: String,
        httpMethod: String = "POST",
        accessToken: String? = null,
        nonce: String? = null,
        randomSource: RandomSource = RandomSource.Secure,
        clock: Clock = Clock.System,
    ) = signDpop(
        JwsContentTypeConstants.DPOP_JWT,
        JsonWebToken(
            jwtId = randomSource.nextBytes(12).encodeToString(Base64UrlStrict),
            httpMethod = httpMethod,
            httpTargetUrl = url,
            accessTokenHash = accessToken?.encodeToByteArray()?.sha256()?.encodeToString(Base64UrlStrict),
            issuedAt = clock.now(),
            nonce = nonce,
        ).also {
            Napier.d("Building DPoP JWT: $it")
        },
        JsonWebToken.serializer(),
    ).getOrThrow().serialize()
}

object BuildClientAttestationJwt {
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
    suspend operator fun invoke(
        signJwt: SignJwtFun<JsonWebToken>,
        clientId: String,
        issuer: String,
        clientKey: JsonWebKey,
        walletName: String? = null,
        walletLink: String? = null,
        lifetime: Duration = 60.minutes,
        clockSkew: Duration = 5.minutes,
        clock: Clock = Clock.System,
    ) = signJwt(
        JwsContentTypeConstants.CLIENT_ATTESTATION_JWT,
        run {
            val now = clock.now()
            JsonWebToken(
                issuer = issuer,
                subject = clientId,
                issuedAt = now - clockSkew,
                expiration = now - clockSkew + lifetime,
                walletName = walletName,
                walletLink = walletLink,
                confirmationClaim = ConfirmationClaim(
                    jsonWebKey = clientKey,
                )
            )
        }.also {
            Napier.d("Building client attestation JWT: $it")
        },
        JsonWebToken.serializer(),
    ).getOrThrow()
}

object BuildClientAttestationPoPJwt {
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
    suspend operator fun invoke(
        signJwt: SignJwtFun<JsonWebToken>,
        clientId: String,
        audience: String,
        nonce: String? = null,
        lifetime: Duration = 10.minutes,
        clockSkew: Duration = 5.minutes,
        randomSource: RandomSource = RandomSource.Secure,
        clock: Clock = Clock.System,
    ) = signJwt(
        JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
        run {
            val now = clock.now()
            JsonWebToken(
                issuer = clientId,
                audience = audience,
                jwtId = randomSource.nextBytes(12).encodeToString(Base64UrlStrict),
                nonce = nonce,
                issuedAt = now - clockSkew,
                expiration = now - clockSkew + lifetime,
            )
        }.also {
            Napier.d("Building client attestation PoP JWT: $it")
        },
        JsonWebToken.serializer(),
    ).getOrThrow()
}