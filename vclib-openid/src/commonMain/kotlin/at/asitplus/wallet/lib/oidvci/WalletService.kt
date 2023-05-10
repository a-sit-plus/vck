package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import kotlinx.datetime.Clock

class WalletService(
    val tokenType: Array<String>,
    val clientId: String = "https://wallet.a-sit.at/app",
    val redirectUrl: String = "$clientId/callback",
    val cryptoService: CryptoService = DefaultCryptoService(),
    val jwsService: JwsService = DefaultJwsService(cryptoService),
) {

    fun createAuthRequest() = AuthorizationRequestParameters(
        responseType = "code",
        clientId = clientId,
        authorizationDetails = AuthorizationDetails(
            type = "openid_credential",
            format = CredentialFormatEnum.JWT_VC,
            types = arrayOf("VerifiableCredential") + tokenType,
        ),
        redirectUrl = redirectUrl,
    )

    fun createTokenRequestParameters(code: String) = TokenRequestParameters(
        grantType = "code",
        code = code,
        redirectUrl = redirectUrl,
        clientId = clientId,
    )

    suspend fun createCredentialRequest(
        tokenResponse: TokenResponseParameters,
        issuerMetadata: IssuerMetadata
    ) = CredentialRequestParameters(
        format = CredentialFormatEnum.JWT_VC,
        types = tokenType,
        proof = CredentialRequestProof(
            proofType = "jwt",
            jwt = jwsService.createSignedJwsAddingParams(
                header = JwsHeader(
                    algorithm = JwsAlgorithm.ES256,
                    type = "openid4vci-proof+jwt",
                ),
                payload = JsonWebToken(
                    issuer = clientId,
                    audience = issuerMetadata.credentialIssuer,
                    issuedAt = Clock.System.now(),
                    nonce = tokenResponse.clientNonce,
                ).serialize().encodeToByteArray(),
                addKeyId = true,
                addJsonWebKey = true
            )!!
        )
    )

}