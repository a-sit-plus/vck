package at.asitplus.wallet.lib.oauth2

import at.asitplus.signum.indispensable.josef.JwsAlgorithm
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.oidvci.DefaultNonceService
import at.asitplus.wallet.lib.oidvci.NonceService

/** Combines access token generation and verification. */
data class TokenService(
    val generation: TokenGenerationService,
    val verification: TokenVerificationService,
    val dpopSigningAlgValuesSupportedStrings: Set<String>? = null,
) {
    companion object {
        fun jwt(
            publicContext: String = "https://wallet.a-sit.at/authorization-server",
            nonceService: NonceService = DefaultNonceService(),
            keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
            issueRefreshTokens: Boolean = false,
            verificationAlgorithms: Collection<JwsAlgorithm> = setOf(JwsAlgorithm.ES256), // per OID4VC HAIP
        ) = TokenService(
            generation = JwtTokenGenerationService(
                nonceService = nonceService,
                publicContext = publicContext,
                jwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
                issueRefreshToken = issueRefreshTokens,
            ),
            verification = JwtTokenVerificationService(
                nonceService = nonceService,
                issuerKey = keyMaterial.jsonWebKey,
            ),
            dpopSigningAlgValuesSupportedStrings = verificationAlgorithms.map { it.identifier }.toSet()

        )

        fun bearer(
            nonceService: NonceService = DefaultNonceService(),
        ) = BearerTokenGenerationService(nonceService = nonceService).let { generationService ->
            TokenService(
                generation = generationService,
                verification = BearerTokenVerificationService(
                    nonceService = nonceService,
                    tokenGenerationService = generationService
                ),
                dpopSigningAlgValuesSupportedStrings = null
            )
        }
    }
}