package at.asitplus.wallet.lib.oauth2

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JwsAlgorithm.Signature
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import kotlin.time.Duration.Companion.days

/**
 * Access token service that combines generation and verification,
 * i.e., it is suitable to be used in an implementation of an OAuth 2.0 Authorization Server.
 */
interface TokenService {
    val generation: TokenGenerationService
    val verification: TokenVerificationService
    val dpopSigningAlgValuesSupportedStrings: Set<String>?
    val supportsRefreshTokens: Boolean

    /**
     * Validates the access token from [authorizationHeader] and returns what it authorizes.
     * Implementations that issued the token themselves also fill [ValidatedAccessToken.userInfoExtended].
     */
    suspend fun validateAccessToken(
        authorizationHeader: String,
        httpRequest: RequestInfo?,
        validatedClientKey: JsonWebKey?,
    ): KmmResult<ValidatedAccessToken> = verification.validateAccessToken(
        tokenOrAuthHeader = authorizationHeader,
        httpRequest = httpRequest,
        validatedClientKey = validatedClientKey
    )

    suspend fun dpopNonce() = generation.dpopNonce()

    @Deprecated("Token Exchange is not supported")
    suspend fun tokenExchange(
        request: TokenRequestParameters,
        expectedResource: String,
        httpRequest: RequestInfo?,
        validatedClientKey: JsonWebKey?,
    ): KmmResult<TokenResponseParameters> = catching {
        throw NotImplementedError()
    }

    companion object {
        /** Build a [TokenService] combining [JwtTokenGenerationService] and [JwtTokenVerificationService]. */
        fun jwt(
            publicContext: String = "https://wallet.a-sit.at/authorization-server",
            nonceService: NonceService = DefaultNonceService(),
            refreshTokenNonceService: NonceService = DefaultNonceService(lifetime = 30.days),
            dpopNonceService: NonceService = DefaultNonceService(),
            keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
            issueRefreshTokens: Boolean = false,
            verificationAlgorithms: Collection<Signature> = setOf(Signature.ES256), // per OID4VC HAIP
        ) = JwtTokenService(
            generation = JwtTokenGenerationService(
                nonceService = nonceService,
                refreshTokenNonceService = refreshTokenNonceService,
                dpopNonceService = dpopNonceService,
                publicContext = publicContext,
                keyMaterial = keyMaterial,
                issueRefreshToken = issueRefreshTokens,
            ),
            verification = JwtTokenVerificationService(
                nonceService = nonceService,
                refreshTokenNonceService = refreshTokenNonceService,
                dpopNonceService = dpopNonceService,
                issuerKey = keyMaterial.jsonWebKey,
                supportedSignatureAlgorithms = verificationAlgorithms,
            ),
            dpopSigningAlgValuesSupportedStrings = verificationAlgorithms.map { it.identifier }.toSet(),
            supportsRefreshTokens = true,
        )

        /** Build a [TokenService] combining [BearerTokenGenerationService] and [BearerTokenVerificationService]. */
        fun bearer(
            nonceService: NonceService = DefaultNonceService(),
            issueRefreshTokens: Boolean = false
        ) = BearerTokenGenerationService(
            nonceService = nonceService,
            issueRefreshToken = issueRefreshTokens
        ).let { generationService ->
            BearerTokenService(
                generation = generationService,
                verification = BearerTokenVerificationService(
                    tokenGenerationService = generationService
                ),
                dpopSigningAlgValuesSupportedStrings = null,
                supportsRefreshTokens = issueRefreshTokens,
            )
        }
    }
}

