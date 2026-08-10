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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.hours
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
        randomSource: RandomSource = RandomSource.Secure
    ): JwsCompactTyped<JsonWebToken> = signDpop(
        type = JwsContentTypeConstants.DPOP_JWT,
        payload = JsonWebToken(
            jwtId = randomSource.nextBytes(12).encodeToString(Base64UrlStrict),
            httpMethod = httpMethod,
            httpTargetUrl = url,
            accessTokenHash = accessToken?.encodeToByteArray()?.sha256()?.encodeToString(Base64UrlStrict),
            issuedAt = Clock.System.now().truncateToSeconds(),
            nonce = nonce,
        ).also {
            Napier.d("Building DPoP JWT: $it")
        },
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
     * @param clientStatus status information for the Wallet Instance.
     * @param walletLink URL for further information about the Wallet Solution.
     * @param lifetime validity period of the assertion (minus the [clockSkew])
     * @param clockSkew duration to subtract from [Clock.System.now] when setting the creation timestamp
     */
    suspend operator fun invoke(
        signJwt: SignJwtFun<JsonWebToken>,
        clientId: String,
        clientKey: JsonWebKey,
        walletName: String = clientId,
        walletVersion: String = "unspecified",
        walletSolutionCertificationInformation: String = "unspecified",
        clientStatus: ClientStatus = ClientStatus(
            status = defaultClientStatus(),
            expiration = Clock.System.now().truncateToSeconds() + 31.days,
        ),
        walletLink: String? = null,
        lifetime: Duration = 60.minutes,
        clockSkew: Duration = 3.minutes,
    ): JwsCompactTyped<JsonWebToken> = signJwt(
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_JWT,
        payload = JsonWebToken(
            subject = clientId,
            issuedAt = Clock.System.now().truncateToSeconds() - clockSkew.absoluteValue,
            expiration = Clock.System.now().truncateToSeconds() - clockSkew.absoluteValue +
                    lifetime.coerceAtMost(24.hours - 1.minutes),
            walletName = walletName,
            walletLink = walletLink,
            walletVersion = walletVersion,
            walletSolutionCertificationInformation = walletSolutionCertificationInformation,
            clientStatus = clientStatus,
            confirmationClaim = ConfirmationClaim(
                jsonWebKey = clientKey,
            )
        ).also {
            Napier.d("Building client attestation JWT: $it")
        },
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()

    private fun defaultClientStatus(): JsonObject = buildJsonObject {
        putJsonObject("status_list") {
            put("idx", 0)
            put("uri", "https://example.org/status/wallet-instance")
        }
    }
}

object BuildClientAttestationPoPJwt {
    /**
     * Client attestation PoP JWT, issued by the client, which can be sent to an OAuth2 Authorization Server if needed,
     * e.g. as HTTP header `OAuth-Client-Attestation-PoP`, see
     * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-10.html)
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
        clockSkew: Duration = 3.minutes,
        randomSource: RandomSource = RandomSource.Secure
    ): JwsCompactTyped<JsonWebToken> = signJwt(
        type = JwsContentTypeConstants.CLIENT_ATTESTATION_POP_JWT,
        // TODO Validate fields against latest draft
        payload = JsonWebToken(
            issuer = clientId,
            audience = audience,
            jwtId = randomSource.nextBytes(12).encodeToString(Base64UrlStrict),
            // Setting both fields here, this changed in draft 10 of OAuth 2.0 Attestation-Based Client Auth
            nonce = nonce,
            challenge = nonce,
            issuedAt = Clock.System.now().truncateToSeconds() - clockSkew.absoluteValue,
            expiration = Clock.System.now().truncateToSeconds() - clockSkew.absoluteValue + lifetime,
        ).also {
            Napier.d("Building client attestation PoP JWT: $it")
        },
        serializer = JsonWebToken.serializer(),
    ).getOrThrow()
}
