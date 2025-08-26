package at.asitplus.wallet.lib.oauth2

import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.OpenIdConstants.TokenTypes
import at.asitplus.openid.TokenRequestParameters
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.signum.indispensable.josef.JwsAlgorithm.Signature
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.NonceService
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidGrant
import io.github.aakira.napier.Napier

/**
 * Access token service that combines generation and verification,
 * i.e., it is suitable to be used in an implementation of an OAuth 2.0 Authorization Server.
 */
interface TokenService {
    val generation: TokenGenerationService
    val verification: TokenVerificationService
    val dpopSigningAlgValuesSupportedStrings: Set<String>?
    val supportsRefreshTokens: Boolean

    /** Validates that the token sent from the client is actually one issued from the known [TokenGenerationService]. */
    suspend fun validateTokenExtractUser(
        authorizationHeader: String,
        request: RequestInfo?,
    ): ValidatedAccessToken

    /**
     * Validates the subject token (that is a token sent by a third party for token exchange) is one issued from
     * [TokenGenerationService]. Callers need to authenticate the client before calling this method.
     */
    suspend fun validateTokenForTokenExchange(
        subjectToken: String,
    ): ValidatedAccessToken

    /**
     * Performs token exchange: Validate the received token from [TokenRequestParameters.subjectToken]
     * and issue a fresh access token.
     * Callers need to make sure that the client has been authenticated before calling this method.
     */
    suspend fun tokenExchange(
        request: TokenRequestParameters,
        httpRequest: RequestInfo?,
        metadata: OAuth2AuthorizationServerMetadata,
    ): TokenResponseParameters {
        Napier.i("tokenExchange: called")
        Napier.d("tokenExchange: called with $request")
        // Client wants to exchange Wallet's access token (probably DPoP-constrained) with a fresh one for userInfo
        if (request.subjectTokenType == null || request.subjectToken == null) {
            throw InvalidGrant("subject_token or subject_token_type is null")
        }
        if (request.resource != metadata.userInfoEndpoint) {
            throw InvalidGrant("resource is not valid, is not for ${metadata.userInfoEndpoint}")
        }
        if (request.requestedTokenType != TokenTypes.ACCESS_TOKEN) {
            throw InvalidGrant("requested_token_type is not valid, must be ${TokenTypes.ACCESS_TOKEN}")
        }
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
            scope = validated.scope
        ).also { Napier.i("tokenExchange returns: $it") }
    }

    companion object {
        fun jwt(
            publicContext: String = "https://wallet.a-sit.at/authorization-server",
            nonceService: NonceService = DefaultNonceService(),
            keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
            issueRefreshTokens: Boolean = false,
            verificationAlgorithms: Collection<Signature> = setOf(Signature.ES256), // per OID4VC HAIP
        ) = JwtTokenService(
            generation = JwtTokenGenerationService(
                nonceService = nonceService,
                publicContext = publicContext,
                keyMaterial = keyMaterial,
                issueRefreshToken = issueRefreshTokens,
            ),
            verification = JwtTokenVerificationService(
                nonceService = nonceService,
                issuerKey = keyMaterial.jsonWebKey,
            ),
            dpopSigningAlgValuesSupportedStrings = verificationAlgorithms.map { it.identifier }.toSet(),
            supportsRefreshTokens = true,
        )

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

