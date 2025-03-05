package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.KEY_ATTESTATION_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.PROOF_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.ProofType
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialScheme
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 15, 2024-12-19.
 */
class CredentialIssuer(
    /**
     * Used to get the user data, and access tokens.
     */
    private val authorizationService: OAuth2AuthorizationServerAdapter,
    /**
     * Used to actually issue the credential.
     */
    private val issuer: Issuer,
    /**
     * List of supported schemes.
     */
    private val credentialSchemes: Set<CredentialScheme>,
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
    private val credentialProvider: CredentialIssuerDataProvider,
) {
    private val supportedCredentialConfigurations = credentialSchemes
        .flatMap { it.toSupportedCredentialFormat(issuer.cryptoAlgorithms).entries }
        .associate { it.key to it.value }

    /**
     * Serve this result JSON-serialized under `/.well-known/openid-credential-issuer`
     * (see [OpenIdConstants.PATH_WELL_KNOWN_CREDENTIAL_ISSUER])
     */
    val metadata: IssuerMetadata by lazy {
        IssuerMetadata(
            issuer = publicContext,
            credentialIssuer = publicContext,
            authorizationServers = setOf(authorizationService.publicContext),
            credentialEndpointUrl = "$publicContext$credentialEndpointPath",
            supportedCredentialConfigurations = supportedCredentialConfigurations,
            batchCredentialIssuance = BatchCredentialIssuanceMetadata(1)
        )
    }

    /**
     * Serve this result JSON-serialized under `/.well-known/jwt-vc-issuer`
     * (see [OpenIdConstants.PATH_WELL_KNOWN_JWT_VC_ISSUER_METADATA]),
     * so that verifiers can look up the keys used to sign credentials.
     */
    val jwtVcMetadata: JwtVcIssuerMetadata by lazy {
        JwtVcIssuerMetadata(
            issuer = publicContext,
            jsonWebKeySet = JsonWebKeySet(setOf(issuer.keyMaterial.jsonWebKey))
        )
    }

    /**
     * Offer all [credentialSchemes] to clients.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     */
    suspend fun credentialOfferWithAuthorizationCode(): CredentialOffer = CredentialOffer(
        credentialIssuer = publicContext,
        configurationIds = credentialSchemes.flatMap { it.toCredentialIdentifier() },
        grants = CredentialOfferGrants(
            authorizationCode = CredentialOfferGrantsAuthCode(
                // TODO remember this state, for subsequent requests from the Wallet
                issuerState = uuid4().toString(),
                authorizationServer = authorizationService.publicContext
            ),
        )
    )

    /**
     * Offer all [credentialSchemes] to clients.
     *
     * Callers need to encode this in [CredentialOfferUrlParameters], and offer the resulting URL to clients,
     * i.e. by displaying a QR Code that can be scanned with wallet apps.
     *
     * @param user used to create the credential when the wallet app requests the credential
     */
    suspend fun credentialOfferWithPreAuthnForUser(
        user: OidcUserInfoExtended,
    ): CredentialOffer = CredentialOffer(
        credentialIssuer = publicContext,
        configurationIds = credentialSchemes.flatMap { it.toCredentialIdentifier() },
        grants = CredentialOfferGrants(
            preAuthorizedCode = CredentialOfferGrantsPreAuthCode(
                preAuthorizedCode = authorizationService.providePreAuthorizedCode(user),
                authorizationServer = authorizationService.publicContext
            )
        )
    )

    /**
     * Verifies the [accessToken] to contain a token from [authorizationService],
     * verifies the proof sent by the client (must contain a nonce sent from [authorizationService]),
     * and issues credentials to the client.
     *
     * Callers need to send the result JSON-serialized back to the client.
     * HTTP status code MUST be 202.
     *
     * @param accessToken The value of HTTP header `Authorization` sent by the client,
     *                    with the prefix `Bearer ` removed, so the plain access token
     * @param params Parameters the client sent JSON-serialized in the HTTP body
     */
    suspend fun credential(
        accessToken: String,
        params: CredentialRequestParameters,
    ): KmmResult<CredentialResponseParameters> = catching {
        val userInfo = authorizationService.getUserInfo(
            accessToken,
            params.credentialIdentifier,
            params.credentialConfigurationId
        ).getOrElse {
            Napier.w("credential: access token not valid", it)
            throw it
        }

        val (credentialScheme, representation) = params.format?.let { params.extractCredentialScheme(it) }
            ?: params.credentialIdentifier?.let { decodeFromCredentialIdentifier(it) }
            ?: params.credentialConfigurationId?.let { extractFromCredentialConfigurationId(it) }
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "credential scheme not known")
                .also { Napier.w("credential: client did not provide correct credential scheme: $params") }

        val issuedCredentials = validateProofExtractSubjectPublicKeys(params).map { subjectPublicKey ->
            val credentialToBeIssued = credentialProvider.getCredential(
                userInfo = userInfo,
                subjectPublicKey = subjectPublicKey,
                credentialScheme = credentialScheme,
                representation = representation.toRepresentation(),
                claimNames = null // OID4VCI: Always issue all claims that are available
            ).getOrElse {
                throw OAuth2Exception(Errors.INVALID_REQUEST, it)
                    .also { Napier.w("credential: did not get any credential from provideUserInfo", it) }
            }
            issuer.issueCredential(
                credential = credentialToBeIssued
            ).getOrElse {
                throw OAuth2Exception(Errors.INVALID_REQUEST, it)
                    .also { Napier.w("credential: issuer did not issue credential", it) }
            }
        }
        // TODO Encrypt optionally
        issuedCredentials.toCredentialResponseParameters()
            .also { Napier.i("credential returns $it") }
    }

    private suspend fun validateProofExtractSubjectPublicKeys(params: CredentialRequestParameters): Set<CryptoPublicKey> =
        params.proof?.validateProof()?.let { setOf(it) }
            ?: params.proofs?.validateProof()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST, "invalid proof")
                .also { Napier.w("credential: client did not provide proof of possession in $params") }

    private suspend fun CredentialRequestProof.validateProof() = when (proofType) {
        ProofType.JWT -> jwtParsed?.validateJwtProof()
        ProofType.ATTESTATION -> attestationParsed?.validateAttestationProof()
        else -> null
    }

    private suspend fun CredentialRequestProofContainer.validateProof() = when (proofType) {
        ProofType.JWT -> jwtParsed?.map { it.validateJwtProof() }?.toSet()
        ProofType.ATTESTATION -> attestationParsed?.map { it.validateAttestationProof() }?.toSet()
        else -> null
    }

    private suspend fun JwsSigned<JsonWebToken>.validateJwtProof(): CryptoPublicKey {
        if (header.type != PROOF_JWT_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF, "invalid typ: ${header.type}")
                .also { Napier.w("client did provide invalid header type in JWT in proof: $header") }
        if (authorizationService.supportsClientNonce) {
            if (payload.nonce == null || !authorizationService.verifyClientNonce(payload.nonce!!))
                throw OAuth2Exception(Errors.INVALID_PROOF, "invalid nonce: ${payload.nonce}")
                    .also { Napier.w("client did provide invalid nonce in JWT in proof: ${payload.nonce}") }
        }
        if (payload.audience == null || payload.audience != publicContext)
            throw OAuth2Exception(Errors.INVALID_PROOF, "invalid audience: ${payload.audience}")
                .also { Napier.w("client did provide invalid audience in JWT in proof: ${payload.audience}") }
        return header.publicKey
            ?: throw OAuth2Exception(Errors.INVALID_PROOF, "could not extract public key")
                .also { Napier.w("client did provide no valid key in header in JWT in proof: $header") }
    }

    private suspend fun JwsSigned<KeyAttestationJwt>.validateAttestationProof(): CryptoPublicKey {
        if (header.type != KEY_ATTESTATION_JWT_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF, "invalid typ: ${header.type}")
                .also { Napier.w("client did provide invalid header type in JWT in proof: $header") }
        if (authorizationService.supportsClientNonce) {
            if (payload.nonce == null || !authorizationService.verifyClientNonce(payload.nonce!!))
                throw OAuth2Exception(Errors.INVALID_PROOF, "invalid nonce: ${payload.nonce}")
                    .also { Napier.w("client did provide invalid nonce in JWT in proof: ${payload.nonce}") }
        }
        if (payload.audience == null || payload.audience != publicContext)
            throw OAuth2Exception(Errors.INVALID_PROOF, "invalid audience: ${payload.audience}")
                .also { Napier.w("client did provide invalid audience in JWT in proof: ${payload.audience}") }
        // TODO Extend validation
        return header.publicKey
            ?: throw OAuth2Exception(Errors.INVALID_PROOF, "could not extract public key")
                .also { Napier.w("client did provide no valid key in header in JWT in proof: $header") }
    }

    private fun extractFromCredentialConfigurationId(credentialConfigurationId: String): Pair<CredentialScheme, CredentialFormatEnum>? =
        supportedCredentialConfigurations[credentialConfigurationId]?.let {
            decodeFromCredentialIdentifier(credentialConfigurationId)
        }
}

@Suppress("DEPRECATION")
private fun CredentialRequestParameters.extractCredentialScheme(format: CredentialFormatEnum) = when (format) {
    CredentialFormatEnum.JWT_VC -> credentialDefinition?.types?.firstOrNull { it != VERIFIABLE_CREDENTIAL }
        ?.let { AttributeIndex.resolveAttributeType(it) }
        ?.let { it to CredentialFormatEnum.JWT_VC }

    CredentialFormatEnum.VC_SD_JWT,
    CredentialFormatEnum.DC_SD_JWT,
        -> sdJwtVcType?.let { AttributeIndex.resolveSdJwtAttributeType(it) }
        ?.let { it to CredentialFormatEnum.DC_SD_JWT }

    CredentialFormatEnum.MSO_MDOC -> docType?.let { AttributeIndex.resolveIsoDoctype(it) }
        ?.let { it to CredentialFormatEnum.MSO_MDOC }

    else -> null
}

fun interface CredentialIssuerDataProvider {

    /**
     * Gets called with the user authorized in [userInfo],
     * a resolved [credentialScheme],
     * the holder key in [subjectPublicKey],
     * and the requested credential [representation].
     * Callers may optionally define some attribute names from [ConstantIndex.CredentialScheme.claimNames] in
     * [claimNames] to request only some claims (if supported by the representation).
     */
    fun getCredential(
        userInfo: OidcUserInfoExtended,
        subjectPublicKey: CryptoPublicKey,
        credentialScheme: CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?,
    ): KmmResult<CredentialToBeIssued>
}
