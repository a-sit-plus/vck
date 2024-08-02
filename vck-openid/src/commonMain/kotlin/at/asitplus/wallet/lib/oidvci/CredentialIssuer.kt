package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.CborWebToken
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.agent.IssuerCredentialDataProvider
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.oidc.OpenIdConstants.Errors
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ProofType
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from [OpenID for Verifiable Credential Issuance]
 * (https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), Draft 13, 2024-02-08.
 */
class CredentialIssuer(
    /**
     * Used to get the user data, and access tokens.
     */
    private val authorizationService: OAuth2AuthorizationServer,
    /**
     * Used to actually issue the credential.
     */
    private val issuer: Issuer,
    /**
     * List of supported schemes.
     */
    private val credentialSchemes: Set<ConstantIndex.CredentialScheme>,
    /**
     * Used in several fields in [IssuerMetadata], to provide endpoint URLs to clients.
     */
    private val publicContext: String = "https://wallet.a-sit.at/credential-issuer",
    /**
     * Used to build [IssuerMetadata.credentialEndpointUrl], i.e. implementers need to forward requests
     * to that URI (which starts with [publicContext]) to [credential].
     */
    private val credentialEndpointPath: String = "/credential",
    /**
     * Used during issuance, when issuing credentials (using [issuer]) with data from [OidcUserInfoExtended]
     */
    private val buildIssuerCredentialDataProviderOverride: (OidcUserInfoExtended) -> IssuerCredentialDataProvider = {
        OAuth2IssuerCredentialDataProvider(it)
    }
) {
    /**
     * Serve this result JSON-serialized under `/.well-known/openid-credential-issuer`
     */
    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServers = setOf(authorizationService.publicContext),
            credentialEndpointUrl = "$publicContext$credentialEndpointPath",
            authorizationEndpointUrl = if (authorizationService is SimpleAuthorizationService)
                authorizationService.publicContext + authorizationService.authorizationEndpointPath
            else null,
            tokenEndpointUrl = if (authorizationService is SimpleAuthorizationService)
                authorizationService.publicContext + authorizationService.tokenEndpointPath
            else null,
            supportedCredentialConfigurations = mutableMapOf<String, SupportedCredentialFormat>().apply {
                credentialSchemes.forEach { putAll(it.toSupportedCredentialFormat(issuer.cryptoAlgorithms)) }
            },
            supportsCredentialIdentifiers = true,
        )
    }

    /**
     * Offer all [credentialSchemes] to clients.
     * Callers may need to transport this in [CredentialOfferUrlParameters] to (HTTPS) clients.
     */
    suspend fun credentialOffer(): CredentialOffer = CredentialOffer(
        credentialIssuer = publicContext,
        configurationIds = credentialSchemes.flatMap { it.toSupportedCredentialFormat(issuer.cryptoAlgorithms).keys },
        grants = CredentialOfferGrants(
            authorizationCode = CredentialOfferGrantsAuthCode(
                issuerState = uuid4().toString(), // TODO remember this state, for subsequent requests from the Wallet
                authorizationServer = authorizationService.publicContext
            ),
            preAuthorizedCode = authorizationService.providePreAuthorizedCode()?.let {
                CredentialOfferGrantsPreAuthCode(
                    preAuthorizedCode = it,
                    authorizationServer = authorizationService.publicContext
                )
            }
        )
    )

    /**
     * Verifies the [accessToken] to contain a token from [authorizationService],
     * verifies the proof sent by the client (must contain a nonce sent from [authorizationService]),
     * and issues credentials to the client.
     * Send the result JSON-serialized back to the client.
     *
     * @param accessToken The value of HTTP header `Authorization` sent by the client,
     *                    with the prefix `Bearer ` removed, so the plain access token
     * @param params Parameters the client sent JSON-serialized in the HTTP body
     */
    suspend fun credential(
        accessToken: String,
        params: CredentialRequestParameters
    ): KmmResult<CredentialResponseParameters> = catching {
        val proof = params.proof
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("credential: client did not provide proof of possession") }
        val subjectPublicKey = when (proof.proofType) {
            ProofType.JWT -> {
                if (proof.jwt == null)
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid proof: $proof") }
                val jwsSigned = JwsSigned.parse(proof.jwt).getOrNull()
                    ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid proof: $proof") }
                val jwt = JsonWebToken.deserialize(jwsSigned.payload.decodeToString()).getOrNull()
                    ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid JWT in proof: $proof") }
                if (jwt.nonce == null || !authorizationService.verifyAndRemoveClientNonce(jwt.nonce!!))
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid nonce in JWT in proof: ${jwt.nonce}") }
                if (jwsSigned.header.type != ProofType.JWT_HEADER_TYPE.stringRepresentation)
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid header type in JWT in proof: ${jwsSigned.header}") }
                if (jwt.audience == null || jwt.audience != publicContext)
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid audience in JWT in proof: ${jwsSigned.header}") }
                jwsSigned.header.publicKey
                    ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide no valid key in header in JWT in proof: ${jwsSigned.header}") }
            }

            ProofType.CWT -> {
                if (proof.cwt == null)
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid proof: $proof") }
                val coseSigned = CoseSigned.deserialize(proof.cwt.decodeToByteArray(Base64UrlStrict)).getOrNull()
                    ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid proof: $proof") }

                val cwt = coseSigned.payload?.let { CborWebToken.deserialize(it).getOrNull() }
                    ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid CWT in proof: $proof") }
                if (cwt.nonce == null || !authorizationService.verifyAndRemoveClientNonce(cwt.nonce!!.decodeToString()))
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid nonce in CWT in proof: ${cwt.nonce}") }
                val header = coseSigned.protectedHeader.value
                if (header.contentType != ProofType.CWT_HEADER_TYPE.stringRepresentation)
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid header type in CWT in proof: $header") }
                if (cwt.audience == null || cwt.audience != publicContext)
                    throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide invalid audience in CWT in proof: $header") }
                header.certificateChain?.let { X509Certificate.decodeFromByteArray(it)?.publicKey }
                    ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                        .also { Napier.w("credential: client did provide no valid key in header in CWT in proof: $header") }
            }

            else -> {
                throw OAuth2Exception(Errors.INVALID_PROOF)
                    .also { Napier.w("credential: client did provide invalid proof type: ${proof.proofType}") }
            }
        }

        val userInfo = authorizationService.getUserInfo(accessToken).getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_TOKEN)
                .also { Napier.w("credential: client did not provide correct token: $accessToken") }

        val issuedCredentialResult = when {
            params.format != null -> {
                val credentialScheme = params.extractCredentialScheme(params.format)
                    ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.w("credential: client did not provide correct credential scheme: ${params}") }
                issuer.issueCredential(
                    subjectPublicKey = subjectPublicKey,
                    credentialScheme = credentialScheme,
                    representation = params.format.toRepresentation(),
                    claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null },
                    dataProviderOverride = buildIssuerCredentialDataProviderOverride(userInfo)
                )
            }

            params.credentialIdentifier != null -> {
                val (credentialScheme, representation) = decodeFromCredentialIdentifier(params.credentialIdentifier)
                    ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                        .also { Napier.w("credential: client did not provide correct credential identifier: ${params.credentialIdentifier}") }
                issuer.issueCredential(
                    subjectPublicKey = subjectPublicKey,
                    credentialScheme = credentialScheme,
                    representation = representation.toRepresentation(),
                    claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null },
                    dataProviderOverride = buildIssuerCredentialDataProviderOverride(userInfo)
                )
            }

            else -> {
                throw OAuth2Exception(Errors.INVALID_REQUEST)
                    .also { Napier.w("credential: client did not provide format or credential identifier in params: $params") }
            }
        }
        val issuedCredential = issuedCredentialResult.getOrElse {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("credential: issuer did not issue credential: $issuedCredentialResult") }
        }
        // TODO Implement Batch Credential Endpoint for more than one credential response

        issuedCredential.toCredentialResponseParameters()
            .also { Napier.i("credential returns $it") }
    }


}

private fun CredentialRequestParameters.extractCredentialScheme(format: CredentialFormatEnum) = when (format) {
    CredentialFormatEnum.JWT_VC -> credentialDefinition?.types?.firstOrNull { it != VERIFIABLE_CREDENTIAL }
        ?.let { AttributeIndex.resolveAttributeType(it) }

    CredentialFormatEnum.VC_SD_JWT,
    CredentialFormatEnum.JWT_VC_SD_UNOFFICIAL -> sdJwtVcType?.let { AttributeIndex.resolveSdJwtAttributeType(it) }

    CredentialFormatEnum.MSO_MDOC -> docType?.let { AttributeIndex.resolveIsoDoctype(it) }
    else -> null
}
