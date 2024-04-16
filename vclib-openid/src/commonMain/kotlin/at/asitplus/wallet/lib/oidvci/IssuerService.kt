package at.asitplus.wallet.lib.oidvci

import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.jws.JsonWebToken
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJwsAlgorithm
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.oidc.AuthenticationRequestParameters
import at.asitplus.wallet.lib.oidc.OpenIdConstants
import at.asitplus.wallet.lib.oidc.OpenIdConstants.BINDING_METHOD_COSE_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_CODE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.GRANT_TYPE_PRE_AUTHORIZED_CODE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ProofTypes
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_PREFIX_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.TOKEN_TYPE_BEARER
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidvci.mdl.RequestedCredentialClaimSpecification
import com.benasher44.uuid.uuid4
import io.ktor.http.*
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlin.coroutines.cancellation.CancellationException

/**
 * Server implementation to issue credentials using
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html).
 * Implemented from Draft `openid-4-verifiable-credential-issuance-1_0-11`, 2023-02-03.
 */
class IssuerService(
    /**
     * Used to actually issue the credential.
     */
    private val issuer: Issuer,
    /**
     * List of supported schemes.
     */
    private val credentialSchemes: Collection<ConstantIndex.CredentialScheme>,
    /**
     * Used to create and verify authorization codes during issuing.
     */
    private val codeService: CodeService = DefaultCodeService(),
    /**
     * Used to create and verify bearer tokens during issuing.
     */
    private val tokenService: TokenService = DefaultTokenService(),
    /**
     * Used to provide challenge to clients to include in proof of posession of key material.
     */
    private val clientNonceService: NonceService = DefaultNonceService(),
    /**
     * Used as [IssuerMetadata.authorizationServers].
     */
    private val authorizationServer: String? = null,
    /**
     * Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients.
     */
    private val publicContext: String = "https://wallet.a-sit.at/",
    /**
     * Used to build [IssuerMetadata.authorizationEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [authorize].
     */
    private val authorizationEndpointPath: String = "/authorize",
    /**
     * Used to build [IssuerMetadata.tokenEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [token].
     */
    private val tokenEndpointPath: String = "/token",
    /**
     * Used to build [IssuerMetadata.credentialEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [credential].
     */
    private val credentialEndpointPath: String = "/credential",
) {

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-credential-issuer`
     */
    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServers = authorizationServer?.let { listOf(it) },
            authorizationEndpointUrl = "$publicContext$authorizationEndpointPath",
            tokenEndpointUrl = "$publicContext$tokenEndpointPath",
            credentialEndpointUrl = "$publicContext$credentialEndpointPath",
            supportedCredentialConfigurations = mutableMapOf<String, SupportedCredentialFormat>().apply {
                credentialSchemes.forEach { putAll(it.toSupportedCredentialFormat()) }
            },
            supportsCredentialIdentifiers = true,
            displayProperties = credentialSchemes.map { DisplayProperties(it.vcType, "en") }
        )
    }

    private fun ConstantIndex.CredentialScheme.toSupportedCredentialFormat() = mapOf(
        this.isoNamespace to SupportedCredentialFormat(
            format = CredentialFormatEnum.MSO_MDOC,
            docType = isoDocType,
            claims = mapOf(
                isoNamespace to claimNames
                    .associateWith { RequestedCredentialClaimSpecification() }
            ),
            supportedBindingMethods = listOf(BINDING_METHOD_COSE_KEY),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        ),
        "$vcType-${CredentialFormatEnum.JWT_VC.text}" to SupportedCredentialFormat(
            format = CredentialFormatEnum.JWT_VC,
            credentialDefinition = SupportedCredentialFormatDefinition(
                types = listOf(VERIFIABLE_CREDENTIAL, vcType),
                credentialSubject = this.claimNames.associateWith { CredentialSubjectMetadataSingle() }
            ),
            supportedBindingMethods = listOf(PREFIX_DID_KEY, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        ),
        "$vcType-${CredentialFormatEnum.VC_SD_JWT.text}" to SupportedCredentialFormat(
            format = CredentialFormatEnum.VC_SD_JWT,
            sdJwtVcType = vcType,
            claims = mapOf(
                isoNamespace to claimNames
                    .associateWith { RequestedCredentialClaimSpecification() }
            ),
            supportedBindingMethods = listOf(PREFIX_DID_KEY, URN_TYPE_JWK_THUMBPRINT),
            supportedSigningAlgorithms = issuer.cryptoAlgorithms.map { it.toJwsAlgorithm().identifier },
        )
    )

    /**
     * Offer all [credentialSchemes] to clients.
     * Callers may need to transport this in [CredentialOfferUrlParameters] to (HTTPS) clients.
     */
    fun credentialOffer(): CredentialOffer = CredentialOffer(
        credentialIssuer = publicContext,
        configurationIds = credentialSchemes.map { it.vcType },
        grants = CredentialOfferGrants(
            authorizationCode = CredentialOfferGrantsAuthCode(
                issuerState = uuid4().toString(), // TODO remember this state, for subsequent requests from the Wallet
                authorizationServer = publicContext // may need to support external AS?
            ),
            preAuthorizedCode = CredentialOfferGrantsPreAuthCode(
                preAuthorizedCode = codeService.provideCode(),
                transactionCode = CredentialOfferGrantsPreAuthCodeTransactionCode(
                    inputMode = "numeric",
                    length = 16,
                ),
                authorizationServer = publicContext // may need to support external AS?,
            )
        )
    )

    /**
     * Send this result as HTTP Header `Location` in a 302 response to the client.
     * @return URL build from client's `redirect_uri` with a `code` query parameter containing a fresh authorization
     * code from [codeService].
     */
    fun authorize(params: AuthenticationRequestParameters): String? {
        // TODO return parameters here directly, callers need to build the URL
        // TODO also need to store the `scope` or `authorization_details`, i.e. may respond with `invalid_scope` here!
        val builder = URLBuilder(params.redirectUrl ?: return null)
        builder.parameters.append(OpenIdConstants.GRANT_TYPE_CODE, codeService.provideCode())
        return builder.buildString()
    }

    /**
     * Verifies the authorization code sent by the client and issues an access token.
     * Send this value JSON-serialized back to the client.
     */
    @Throws(OAuth2Exception::class)
    fun token(params: TokenRequestParameters): TokenResponseParameters {
        // TODO This is part of the Authorization Server
        when (params.grantType) {
            GRANT_TYPE_CODE -> if (params.code == null || !codeService.verifyCode(params.code))
                throw OAuth2Exception(Errors.INVALID_CODE)

            GRANT_TYPE_PRE_AUTHORIZED_CODE -> if (params.preAuthorizedCode == null || !codeService.verifyCode(params.preAuthorizedCode))
                throw OAuth2Exception(Errors.INVALID_GRANT)

            else ->
                throw OAuth2Exception("No valid grant_type: ${params.grantType}")
        }
        if (params.authorizationDetails != null) {
            // TODO verify
            // params.authorizationDetails.claims
            params.authorizationDetails.credentialIdentifiers?.forEach {
                if (!credentialSchemes.map { it.vcType }.contains(it)) {
                    throw OAuth2Exception(Errors.INVALID_GRANT)
                }
            }
        }
        return TokenResponseParameters(
            accessToken = tokenService.provideToken(),
            tokenType = TOKEN_TYPE_BEARER,
            expires = 3600,
            clientNonce = clientNonceService.provideNonce(),
            authorizationDetails = params.authorizationDetails?.let {
                // TODO supported credential identifiers!
                listOf(it)
            }
        )
    }

    /**
     * Verifies the [authorizationHeader] to contain a token from [tokenService],
     * verifies the proof sent by the client (must contain a nonce from [clientNonceService]),
     * and issues credentials to the client.
     * Send the result JSON-serialized back to the client.
     *
     * @param authorizationHeader The value of HTTP header `Authorization` sent by the client
     * @param params Parameters the client sent JSON-serialized in the HTTP body
     */
    @Throws(OAuth2Exception::class, CancellationException::class)
    suspend fun credential(
        authorizationHeader: String, // TODO Change interface to only contain access token, nothing else
        params: CredentialRequestParameters
    ): CredentialResponseParameters {
        if (!tokenService.verifyToken(authorizationHeader.removePrefix(TOKEN_PREFIX_BEARER)))
            throw OAuth2Exception(Errors.INVALID_TOKEN)
        val proof = params.proof
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
        // TODO also support `cwt` as proof
        if (proof.proofType != ProofTypes.JWT || proof.jwt == null)
            throw OAuth2Exception(Errors.INVALID_PROOF)
        val jwsSigned = JwsSigned.parse(proof.jwt)
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString()).getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
        // TODO verify required claims in OID4VCI 7.2.1.1
        if (jwt.nonce == null || !clientNonceService.verifyAndRemoveNonce(jwt.nonce!!))
            throw OAuth2Exception(Errors.INVALID_PROOF)
        if (jwsSigned.header.type != ProofTypes.JWT_HEADER_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF)
        val subjectPublicKey = jwsSigned.header.publicKey
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)

        val issuedCredentialResult = if (params.format != null) {
            issuer.issueCredential(
                subjectPublicKey = subjectPublicKey,
                attributeTypes = listOfNotNull(params.sdJwtVcType, params.docType)
                        + (params.credentialDefinition?.types?.toList() ?: listOf()),
                representation = params.format.toRepresentation(),
                claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null }
            )
        } else if (params.credentialIdentifier != null) {
            // TODO this delimiter is probably not safe
            val representation = CredentialFormatEnum.parse(params.credentialIdentifier.substringAfterLast("-"))
                ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
            // TODO what to do in case of ISO, look at string constants from EUDIW
            val vcType = params.credentialIdentifier.substringBeforeLast("-")
            issuer.issueCredential(
                subjectPublicKey = subjectPublicKey,
                attributeTypes = listOf(vcType),
                representation = representation.toRepresentation(),
                claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null }
            )
        } else {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        if (issuedCredentialResult.successful.isEmpty()) {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
        }
        // TODO Implement Batch Credential Endpoint for more than one credential response
        return issuedCredentialResult.successful.first().toCredentialResponseParameters()
    }

    private fun Issuer.IssuedCredential.toCredentialResponseParameters() = when (this) {
        is Issuer.IssuedCredential.Iso -> CredentialResponseParameters(
            format = CredentialFormatEnum.MSO_MDOC,
            credential = issuerSigned.serialize().encodeToString(Base64UrlStrict),
        )

        is Issuer.IssuedCredential.VcJwt -> CredentialResponseParameters(
            format = CredentialFormatEnum.JWT_VC,
            credential = vcJws,
        )

        is Issuer.IssuedCredential.VcSdJwt -> CredentialResponseParameters(
            format = CredentialFormatEnum.VC_SD_JWT,
            credential = vcSdJwt,
        )
    }

}

private fun CredentialFormatEnum.toRepresentation() = when (this) {
    CredentialFormatEnum.JWT_VC_SD_UNOFFICIAL -> ConstantIndex.CredentialRepresentation.SD_JWT
    CredentialFormatEnum.VC_SD_JWT -> ConstantIndex.CredentialRepresentation.SD_JWT
    CredentialFormatEnum.MSO_MDOC -> ConstantIndex.CredentialRepresentation.ISO_MDOC
    else -> ConstantIndex.CredentialRepresentation.PLAIN_JWT
}

class OAuth2Exception(val error: String, val errorDescription: String? = null) : Throwable(error) {

}