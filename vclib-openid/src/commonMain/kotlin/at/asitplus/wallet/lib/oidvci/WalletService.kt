package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import kotlinx.datetime.Clock

/**
 * Client service to retrieve credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
 */
class WalletService(
    private val credentialScheme: ConstantIndex.CredentialScheme,
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val cryptoService: CryptoService = DefaultCryptoService(),
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
) {

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl])
     */
    fun createAuthRequest() = AuthorizationRequestParameters(
        responseType = "code",
        clientId = clientId,
        authorizationDetails = AuthorizationDetails(
            type = "openid_credential",
            format = CredentialFormatEnum.JWT_VC,
            types = arrayOf("VerifiableCredential") + credentialScheme.vcType,
        ),
        redirectUrl = redirectUrl,
    )

    /**
     * Send the result as POST parameters (form-encoded)to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl])
     */
    fun createTokenRequestParameters(code: String) = TokenRequestParameters(
        grantType = "code",
        code = code,
        redirectUrl = redirectUrl,
        clientId = clientId,
    )

    /**
     * Send the result as JSON-serialized content to the server at `/credential` (or more specific
     * [IssuerMetadata.credentialEndpointUrl]).
     * Also send along the [TokenResponseParameters.accessToken] from [tokenResponse] in HTTP header `Authorization`
     * as value `Bearer accessTokenValue` (depending on the [TokenResponseParameters.tokenType]).
     */
    suspend fun createCredentialRequest(
        tokenResponse: TokenResponseParameters,
        issuerMetadata: IssuerMetadata
    ) = CredentialRequestParameters(
        format = CredentialFormatEnum.JWT_VC,
        types = arrayOf("VerifiableCredential") + credentialScheme.vcType,
        proof = CredentialRequestProof(
            proofType = "jwt",
            jwt = jwsService.createSignedJwsAddingParams(
                header = JwsHeader(
                    algorithm = cryptoService.jwsAlgorithm,
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