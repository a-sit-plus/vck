package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OpenIdConstants.TokenTypes
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm.Signature
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidGrant
import io.github.aakira.napier.Napier
import kotlin.time.Duration.Companion.days

/**
 * Access token service that combines generation and verification,
 * i.e., it is suitable to be used in an implementation of an OAuth 2.0 Authorization Server.
 *
 * Also implements [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).
 */
interface TokenService {
    val generation: TokenGenerationService
    val verification: TokenVerificationService
    val dpopSigningAlgValuesSupportedStrings: Set<String>?
    val supportsRefreshTokens: Boolean

    /**
     * Provides information about the access token from [authorizationHeader], if it has been issued by [generation].
     * **Access token needs to be validated before (see [TokenVerificationService.validateAccessToken])**
     */
    suspend fun readUserInfo(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken

    /**
     * Validates the subject token (that is a token sent by a third party) for token exchange) is one issued from
     * [TokenGenerationService]. Callers need to authenticate the client before calling this method.
     */
    suspend fun validateTokenForTokenExchange(
        subjectToken: String,
    ): ValidatedAccessToken

    /**
     * [OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693):
     * Validate the received token from [TokenRequestParameters.subjectToken] and issue a fresh access token.
     * Callers need to make sure that the client has been authenticated before calling this method.
     */
    suspend fun tokenExchange(
        request: TokenRequestParameters,
        expectedResource: String,
        httpRequest: RequestInfo?,
    ): TokenResponseParameters {
        Napier.i("tokenExchange: called")
        Napier.d("tokenExchange: called with $request")
        // Client wants to exchange Wallet's access token (probably DPoP-constrained) with a fresh one for userInfo
        if (request.subjectTokenType == null || request.subjectToken == null) {
            throw InvalidGrant("subject_token or subject_token_type is null")
        }
        if (request.resource != expectedResource) {
            throw InvalidGrant("resource is not valid, is not for $expectedResource")
        }
        if (request.requestedTokenType != TokenTypes.ACCESS_TOKEN) {
            throw InvalidGrant("requested_token_type is not valid, must be ${TokenTypes.ACCESS_TOKEN}")
        }
        val validatedClientKey = verification.extractValidatedClientKey(httpRequest).getOrThrow()
        val validated = validateTokenForTokenExchange(
            subjectToken = request.subjectToken!!,
        ).apply {
            if (userInfoExtended == null)
                throw InvalidGrant("subject_token is not valid, no stored user")
        }
        return generation.buildToken(
            userInfo = validated.userInfoExtended!!,
            httpRequest = httpRequest,
            authorizationDetails = validated.authorizationDetails,
            scope = validated.scope,
            validatedClientKey = validatedClientKey,
        ).also { Napier.i("tokenExchange returns"); Napier.d("tokenExchange returns $it") }
    }

    suspend fun dpopNonce() = generation.dpopNonce()

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
            ),
            dpopSigningAlgValuesSupportedStrings = verificationAlgorithms.map { it.identifier }.toSet(),
            supportsRefreshTokens = true,
        )

        /** Build a [TokenService] combining [BearerTokenGenerationService] and [BearerTokenVerificationService]. */
        fun bearer(
            nonceService: NonceService = DefaultNonceService(),
        ) = BearerTokenGenerationService(
            nonceService = nonceService
        ).let { generationService ->
            BearerTokenService(
                generation = generationService,
                verification = BearerTokenVerificationService(
                    tokenGenerationService = generationService
                ),
                dpopSigningAlgValuesSupportedStrings = null,
                supportsRefreshTokens = false,
            )
        }
    }
}

