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

/** Combines access token generation and verification. */
class TokenService(
    val generation: TokenGenerationService,
    val verification: TokenVerificationService,
    val dpopSigningAlgValuesSupportedStrings: Set<String>?,
    val supportsRefreshTokens: Boolean,
) {
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
        val validated = verification.validateTokenForTokenExchange(
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
        ) = JwtTokenGenerationService(
            nonceService = nonceService,
            publicContext = publicContext,
            keyMaterial = keyMaterial,
            issueRefreshToken = issueRefreshTokens,
        ).let { generationService ->
            TokenService(
                generation = generationService,
                verification = JwtTokenVerificationService(
                    nonceService = nonceService,
                    issuerKey = keyMaterial.jsonWebKey,
                    tokenGenerationService = generationService
                ),
                dpopSigningAlgValuesSupportedStrings = verificationAlgorithms.map { it.identifier }.toSet(),
                supportsRefreshTokens = true,
            )
        }

        fun bearer(
            nonceService: NonceService = DefaultNonceService(),
        ) = BearerTokenGenerationService(nonceService = nonceService).let { generationService ->
            TokenService(
                generation = generationService,
                verification = BearerTokenVerificationService(
                    nonceService = nonceService,
                    tokenGenerationService = generationService
                ),
                dpopSigningAlgValuesSupportedStrings = null,
                supportsRefreshTokens = false,
            )
        }
    }
}