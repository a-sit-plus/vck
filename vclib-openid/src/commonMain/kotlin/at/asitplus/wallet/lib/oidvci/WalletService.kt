package at.asitplus.wallet.lib.oidvci

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultCryptoService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JsonWebToken
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.CREDENTIAL_TYPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import kotlinx.datetime.Clock

/**
 * Client service to retrieve credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
 */
class WalletService(
    private val credentialScheme: ConstantIndex.CredentialScheme,
    private val credentialRepresentation: ConstantIndex.CredentialRepresentation,
    /**
     * Pass names of attributes the credential shall contain, e.g. [at.asitplus.wallet.lib.iso.MobileDrivingLicenceDataElements]
     */
    private val requestedAttributes: Collection<String>? = null,
    private val clientId: String = "https://wallet.a-sit.at/app",
    private val redirectUrl: String = "$clientId/callback",
    private val cryptoService: CryptoService = DefaultCryptoService(),
    private val jwsService: JwsService = DefaultJwsService(cryptoService),
) {

    /**
     * Send the result as parameters (either POST or GET) to the server at `/authorize` (or more specific
     * [IssuerMetadata.authorizationEndpointUrl])
     */
    fun createAuthRequest() = AuthenticationRequestParameters(
        responseType = GRANT_TYPE_CODE,
        clientId = clientId,
        authorizationDetails = credentialRepresentation.toAuthorizationDetails(),
        redirectUrl = redirectUrl,
    )

    /**
     * Send the result as POST parameters (form-encoded)to the server at `/token` (or more specific
     * [IssuerMetadata.tokenEndpointUrl])
     */
    fun createTokenRequestParameters(code: String) = TokenRequestParameters(
        grantType = GRANT_TYPE_CODE,
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
    ): CredentialRequestParameters {
        // NOTE: Specification is missing a proof type for binding method `cose_key`, so we'll use JWT
        val proof = CredentialRequestProof(
            proofType = OpenIdConstants.ProofTypes.JWT,
            jwt = jwsService.createSignedJwsAddingParams(
                header = JwsHeader(
                    algorithm = cryptoService.jwsAlgorithm,
                    type = OpenIdConstants.ProofTypes.JWT_HEADER_TYPE,
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
        return credentialRepresentation.toCredentialRequestParameters(proof)
    }

    private fun ConstantIndex.CredentialRepresentation.toAuthorizationDetails() = when (this) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        ConstantIndex.CredentialRepresentation.SD_JWT -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = toFormat(),
            types = arrayOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType,
            claims = requestedAttributes?.toRequestedClaims(),
        )

        ConstantIndex.CredentialRepresentation.ISO_MDOC -> AuthorizationDetails(
            type = CREDENTIAL_TYPE_OPENID,
            format = toFormat(),
            docType = credentialScheme.isoDocType,
            types = arrayOf(credentialScheme.vcType),
            claims = requestedAttributes?.toRequestedClaims()
        )
    }

    private fun ConstantIndex.CredentialRepresentation.toCredentialRequestParameters(proof: CredentialRequestProof) =
        when (this) {
            ConstantIndex.CredentialRepresentation.PLAIN_JWT,
            ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialRequestParameters(
                format = toFormat(),
                claims = requestedAttributes?.toRequestedClaims(),
                types = arrayOf(VERIFIABLE_CREDENTIAL) + credentialScheme.vcType,
                proof = proof
            )

            ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialRequestParameters(
                format = toFormat(),
                docType = credentialScheme.isoDocType,
                claims = requestedAttributes?.toRequestedClaims(),
                types = arrayOf(credentialScheme.vcType),
                proof = proof
            )
        }

    private fun Collection<String>.toRequestedClaims() =
        mapOf(credentialScheme.isoNamespace to this.associateWith { RequestedCredentialClaimSpecification() })

}

private fun ConstantIndex.CredentialRepresentation.toFormat() = when (this) {
    ConstantIndex.CredentialRepresentation.PLAIN_JWT -> CredentialFormatEnum.JWT_VC
    ConstantIndex.CredentialRepresentation.SD_JWT -> CredentialFormatEnum.JWT_VC_SD
    ConstantIndex.CredentialRepresentation.ISO_MDOC -> CredentialFormatEnum.MSO_MDOC
}
