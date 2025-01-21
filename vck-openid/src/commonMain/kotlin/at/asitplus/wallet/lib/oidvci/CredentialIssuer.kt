package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.*
import at.asitplus.openid.OpenIdConstants.Errors
import at.asitplus.openid.OpenIdConstants.PROOF_CWT_TYPE
import at.asitplus.openid.OpenIdConstants.PROOF_JWT_TYPE
import at.asitplus.openid.OpenIdConstants.ProofType
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CborWebToken
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JsonWebToken
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.CredentialToBeIssued
import at.asitplus.wallet.lib.agent.Issuer
import at.asitplus.wallet.lib.data.AttributeIndex
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_CREDENTIAL
import at.asitplus.wallet.lib.data.vckJsonSerializer
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.builtins.ByteArraySerializer

/**
 * Server implementation to issue credentials using OID4VCI.
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * , Draft 14, 2024-08-21.
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
    private val credentialProvider: CredentialIssuerDataProvider,
) {
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
            supportedCredentialConfigurations = credentialSchemes
                .flatMap { it.toSupportedCredentialFormat(issuer.cryptoAlgorithms).entries }
                .associate { it.key to it.value },
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
     * i.e. by displaying a QR Code that can be scanned with wallet appps.
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
     *
     * @param accessToken The value of HTTP header `Authorization` sent by the client,
     *                    with the prefix `Bearer ` removed, so the plain access token
     * @param params Parameters the client sent JSON-serialized in the HTTP body
     */
    suspend fun credential(
        accessToken: String,
        params: CredentialRequestParameters,
    ): KmmResult<CredentialResponseParameters> = catching {
        val subjectPublicKey = validateProofExtractSubjectPublicKey(params)

        val userInfo = authorizationService.getUserInfo(accessToken).getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_TOKEN)
                .also { Napier.w("credential: client did not provide correct token: $accessToken") }

        val (credentialScheme, representation) = params.format?.let { params.extractCredentialScheme(it) }
            ?: params.credentialIdentifier?.let { decodeFromCredentialIdentifier(it) }
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("credential: client did not provide correct credential scheme: $params") }

        val claimNames = params.claims?.map { it.value.keys }?.flatten()?.ifEmpty { null }

        val credentialToBeIssued = credentialProvider.getCredential(
            userInfo = userInfo,
            subjectPublicKey = subjectPublicKey,
            credentialScheme = credentialScheme,
            representation = representation.toRepresentation(),
            claimNames = claimNames
        ).getOrElse {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("credential: did not get any credential from provideUserInfo", it) }
        }

        val issuedCredential = issuer.issueCredential(
            credential = credentialToBeIssued
        ).getOrElse {
            throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("credential: issuer did not issue credential", it) }
        }

        issuedCredential.toCredentialResponseParameters()
            .also { Napier.i("credential returns $it") }
    }

    private suspend fun validateProofExtractSubjectPublicKey(params: CredentialRequestParameters): CryptoPublicKey =
        params.proof?.validateProof()
            ?: params.proofs?.validateProof()
            ?: throw OAuth2Exception(Errors.INVALID_REQUEST)
                .also { Napier.w("credential: client did not provide proof of possession") }

    private suspend fun CredentialRequestProof.validateProof() = when (proofType) {
        ProofType.JWT -> jwt?.validateJwtProof()
        ProofType.CWT -> cwt?.validateCwtProof()
        else -> null
    }

    private suspend fun CredentialRequestProofContainer.validateProof() = when (proofType) {
        ProofType.JWT -> jwt?.map { it.validateJwtProof() }?.toSet()?.singleOrNull()
        else -> null
    }

    private suspend fun String.validateJwtProof(): CryptoPublicKey {
        val jwsSigned =
            JwsSigned.deserialize<JsonWebToken>(JsonWebToken.serializer(), this, vckJsonSerializer).getOrNull()
                ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                    .also { Napier.w("client did provide invalid proof: $this") }
        val jwt = jwsSigned.payload
        if (jwsSigned.header.type != PROOF_JWT_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid header type in JWT in proof: ${jwsSigned.header}") }
        if (authorizationService.supportsClientNonce)
            if (jwt.nonce == null || !authorizationService.verifyClientNonce(jwt.nonce!!))
                throw OAuth2Exception(Errors.INVALID_PROOF)
                    .also { Napier.w("client did provide invalid nonce in JWT in proof: ${jwt.nonce}") }
        if (jwt.audience == null || jwt.audience != publicContext)
            throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid audience in JWT in proof: ${jwsSigned.header}") }
        return jwsSigned.header.publicKey
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide no valid key in header in JWT in proof: ${jwsSigned.header}") }
    }

    /**
     * Removed in OID4VCI Draft 14, kept here for a bit of backwards-compatibility
     */
    private suspend fun String.validateCwtProof(): CryptoPublicKey {
        val coseSigned = CoseSigned.deserialize(ByteArraySerializer(), decodeToByteArray(Base64UrlStrict)).getOrNull()
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid proof: $this") }
        val cwt = coseSigned.payload?.let { CborWebToken.deserialize(it).getOrNull() }
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid CWT in proof: $this") }
        if (cwt.nonce == null || !authorizationService.verifyClientNonce(cwt.nonce!!.decodeToString()))
            throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid nonce in CWT in proof: ${cwt.nonce}") }
        val header = coseSigned.protectedHeader
        if (header.contentType != PROOF_CWT_TYPE)
            throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid header type in CWT in proof: $header") }
        if (cwt.audience == null || cwt.audience != publicContext)
            throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide invalid audience in CWT in proof: $header") }
        return header.certificateChain?.let { X509Certificate.decodeFromByteArray(it)?.publicKey }
            ?: throw OAuth2Exception(Errors.INVALID_PROOF)
                .also { Napier.w("client did provide no valid key in header in CWT in proof: $header") }
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
        credentialScheme: ConstantIndex.CredentialScheme,
        representation: ConstantIndex.CredentialRepresentation,
        claimNames: Collection<String>?,
    ): KmmResult<CredentialToBeIssued>
}