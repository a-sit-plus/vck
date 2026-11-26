package at.asitplus.wallet.lib.oidvci

/*
 * Software Name : VC-K
 * SPDX-FileCopyrightText: Copyright (c) A-SIT Plus GmbH
 * SPDX-License-Identifier: Apache-2.0
 *
 * Modifications:
 * - According to the W3C Verifiable Credential Data Model 1.1 https://www.w3.org/TR/vc-data-model-1.1/#jwt-encoding,
 * "iss MUST represent the issuer property of a verifiable credential or the holder property of a verifiable presentation."
 * So in this case the issuer should be the wallet holder, represented by it's DID.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 * - Added support for configurable key binding method selection via resolveKeyBindingMethod,
 * allowing the credential request proof JWS header to embed either an inline JsonWebKey (jwk)
 * or a DID URL key identifier (kid), as required by the OID4VCI specification.
 * Exactly one of jwk or kid must be provided; supplying both or neither raises an IllegalArgumentException.
 * The default behaviour (embed jwk inline) is preserved for backward compatibility.
 * SPDX-FileCopyrightText: Copyright (c) Orange Business
 *
 * This software is distributed under the Apache License 2.0,
 * see the "LICENSE" file for more details
 */

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferUrlParameters
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJsonLd
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwtJsonLd
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.openid.decodeFromQuery
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer.CredentialResponse
import at.asitplus.wallet.lib.openid.getUserSignatureCancellationException
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import com.benasher44.uuid.uuid4
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.json.decodeFromJsonElement
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads

/**
 * Client service to retrieve credentials using OID4VCI
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class OpenId4VciClient @JvmOverloads constructor(
    /**
     * Used as the issuer in credential proofs when [createCredential] gets no `clientId`. Deprecated, as the `client_id`
     * belongs to the OAuth 2.0 client: [OpenId4VciProtocolClient.createCredential] passes the one of its [OAuth2Client].
     */
    clientId: String = "https://wallet.a-sit.at/app",
    /** Handles credential request encryption and credential response decryption. */
    private val encryptionService: WalletEncryptionService = WalletEncryptionService(),
    /** First one to create a proof for a given credential is selected for the [CredentialRequestParameters]. */
    private val proofCreators: List<ProofCreator>,
) {

    private val defaultClientId = clientId

    /**
     * What [JwtProofCreator] and [AttestationProofCreator] pass to their `loadKeyAttestation`, to load a key
     * attestation (OpenID4VCI 1.0, Appendix D) that the credential issuer accepts for the requested credential.
     */
    data class KeyAttestationInput(
        /** The Credential Issuer Identifier the proof is created for. */
        val credentialIssuer: String?,
        /**
         * The `c_nonce` of the credential issuer, if it has a Nonce Endpoint, which has to be the `nonce` of the key
         * attestation then (Appendix F.1 and F.3).
         */
        val clientNonce: String?,
        /** The `proof_signing_alg_values_supported` of the proof type (12.2.4). */
        val supportedAlgorithms: Collection<String>?,
        /**
         * The `key_attestations_required` of the proof type (12.2.4), i.e. the `key_storage` and `user_authentication`
         * values (Appendix D.2) the credential issuer accepts, `null` if it states none for this proof type.
         */
        val requirements: KeyAttestationRequired?,
        /**
         * The keys to attest, in order, the one signing a `jwt` proof first (TS3, 2.2.2.1); empty if the loader
         * chooses them.
         */
        val keys: List<CryptoPublicKey> = emptyList(),
    )

    sealed interface CredentialRequest {
        /** `kid` of the key this request advertised for encrypting its response, if any. */
        val credentialResponseEncryptionKeyId: String?

        /**
         * The keys this request's proofs prove, which the issued credentials have to be bound to. Recorded at creation,
         * as a proof may name its key by `kid` only; empty if unknown, e.g. for a parsed request.
         */
        val proofKeys: Set<CryptoPublicKey>

        /**
         * Send [request] as JSON-serialized content to the server at [IssuerMetadata.credentialEndpointUrl] with media
         * type `application/json` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JSON]).
         */
        data class Plain @JvmOverloads constructor(
            val request: CredentialRequestParameters,
            override val proofKeys: Set<CryptoPublicKey> = emptySet(),
        ) : CredentialRequest {
            override val credentialResponseEncryptionKeyId: String?
                get() = request.credentialResponseEncryption?.jsonWebKey?.keyId
        }

        /**
         * Send [request] as JWE-serialized content to the server at [IssuerMetadata.credentialEndpointUrl] with media
         * type `application/jwt` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JWT]).
         */
        data class Encrypted @JvmOverloads constructor(
            val request: JweEncrypted,
            override val credentialResponseEncryptionKeyId: String? = null,
            override val proofKeys: Set<CryptoPublicKey> = emptySet(),
        ) : CredentialRequest

        companion object {
            fun parse(input: String): KmmResult<CredentialRequest> = catching {
                if (input.count { it == '.' } == 4)
                    Encrypted(JweEncrypted.deserialize(input).getOrThrow())
                else
                    Plain(joseCompliantSerializer.decodeFromString<CredentialRequestParameters>(input))
            }
        }
    }

    data class RequestOptions @JvmOverloads constructor(
        /**
         * Credential type to request
         */
        val credentialScheme: CredentialScheme,
        /**
         * Required representation, see [CredentialRepresentation]
         */
        val representation: CredentialRepresentation = PLAIN_JWT,
        /**
         * Opaque value which will be returned by the OpenId Provider
         */
        val state: String = uuid4().toString(),
    )

    /** A credential offer passed by value, or the `credential_offer_uri` to load it from. */
    internal sealed interface CredentialOfferInput {
        data class ByValue(val offer: CredentialOffer) : CredentialOfferInput
        data class ByReference(val uri: String) : CredentialOfferInput
    }

    /**
     * Parses [input] as either a JSON-encoded [CredentialOffer], or a credential offer URL with an embedded
     * `credential_offer` or a `credential_offer_uri`, without retrieving anything.
     */
    internal fun parseCredentialOfferInput(input: String): CredentialOfferInput =
        if (input.trimStart().startsWith("{")) {
            CredentialOfferInput.ByValue(input.decodeCredentialOffer())
        } else {
            val parameters = catchingUnwrapped {
                Url(input).decodeFromQuery<CredentialOfferUrlParameters>()
            }.getOrElse {
                throw InvalidRequest("could not parse credential offer URL", it)
            }
            parameters.credentialOffer?.let { offer ->
                CredentialOfferInput.ByValue(
                    catchingUnwrapped {
                        joseCompliantSerializer.decodeFromJsonElement<CredentialOffer>(offer)
                    }.getOrElse {
                        throw InvalidRequest("could not parse embedded credential offer", it)
                    }
                )
            } ?: parameters.credentialOfferUrl?.let { CredentialOfferInput.ByReference(it) }
            ?: throw InvalidRequest("credential offer URL contains neither credential_offer nor credential_offer_uri")
        }

    /** Decodes a JSON-encoded [CredentialOffer], e.g. the resource referenced by `credential_offer_uri`. */
    internal fun String.decodeCredentialOffer(): CredentialOffer = catchingUnwrapped {
        joseCompliantSerializer.decodeFromString<CredentialOffer>(this)
    }.getOrElse {
        throw InvalidRequest("could not parse credential offer", it)
    }

    /**
     * Build authorization details for use in [OAuth2Client.createAuthRequest].
     *
     * @param credentialConfigurationId which credentials to request, i.e.
     * one of the keys from [IssuerMetadata.supportedCredentialConfigurations],
     * or from [CredentialOffer.configurationIds]
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    fun buildAuthorizationDetails(
        credentialConfigurationId: String,
        authorizationServers: Set<String>? = null,
    ): Set<OpenIdAuthorizationDetails> = buildAuthorizationDetails(
        credentialConfigurationIds = setOf(credentialConfigurationId),
        authorizationServers = authorizationServers
    )

    /**
     * Build authorization details for use in [OAuth2Client.createAuthRequest].
     *
     * @param credentialConfigurationIds which credentials to request, i.e.
     * filtered keys from [IssuerMetadata.supportedCredentialConfigurations],
     * or from [CredentialOffer.configurationIds]
     * @param authorizationServers from [IssuerMetadata.authorizationServers]
     */
    fun buildAuthorizationDetails(
        credentialConfigurationIds: Set<String>,
        authorizationServers: Set<String>? = null,
    ): Set<OpenIdAuthorizationDetails> = credentialConfigurationIds.map {
        OpenIdAuthorizationDetails(
            credentialConfigurationId = it,
            locations = authorizationServers,
        )
    }.toSet()

    /**
     * Extract [SupportedCredentialFormat] from [metadata] by filtering according to [requestOptions].
     */
    fun selectSupportedCredentialFormat(
        requestOptions: RequestOptions,
        metadata: IssuerMetadata,
    ): SupportedCredentialFormat? = metadata.supportedCredentialConfigurations.values.filter {
        it.format.toRepresentation() == requestOptions.representation
    }.firstOrNull {
        when (requestOptions.representation) {
            PLAIN_JWT -> when (it) {
                is SupportedCredentialFormatW3cVcJwt -> it.credentialDefinition.types
                is SupportedCredentialFormatW3cVcJwtJsonLd -> it.credentialDefinition.type
                is SupportedCredentialFormatW3cVcJsonLd -> it.credentialDefinition.type
                else -> listOf()
            }.contains(requestOptions.credentialScheme.vcType!!)

            SD_JWT -> when (it) {
                is SupportedCredentialFormatSdJwt -> it.sdJwtVcType
                else -> null
            } == requestOptions.credentialScheme.sdJwtType!!

            ISO_MDOC -> when (it) {
                is SupportedCredentialFormatIsoMdoc -> it.docType
                else -> null
            } == requestOptions.credentialScheme.isoDocType!!
        }
    }

    /**
     * Prepared credential request from [prepareCredentialRequests], to be put one-by-one into [createCredential]
     * after fetching the client nonce
     */
    data class PreparedCredentialRequest(
        /**
         * The `credential_configuration_id` of the requested credential, also for a request by `credential_identifier`,
         * whose authorization details name it (OpenID4VCI 1.0, 5.1.1, 6.2), as the identifier itself is opaque.
         */
        val credentialConfigurationId: String,
        /**
         * Either the `credential_identifier` or the `credential_configuration_id` of the requested credential, still
         * without `proofs` and `credential_response_encryption` (OpenID4VCI 1.0, 8.2).
         */
        val credentialRequestParameters: CredentialRequestParameters,
        /** The configuration of the requested credential, which its proof and decoding the response depend on. */
        val credentialFormat: SupportedCredentialFormat,
    )

    /**
     * Prepares the credential requests the access token of [tokenResponse] grants for the credentials of
     * [credentialFormats], each with the configuration its proof and response depend on, still without proofs and
     * encryption. Create each request with its own `c_nonce` right before sending it with
     * [OpenId4VciProtocolClient.credentialRequest], which adds the access token from [tokenResponse] and, for
     * DPoP-bound tokens, the DPoP proof, and parses the response.
     *
     * Fails if the token grants none of [credentialFormats].
     *
     * @param tokenResponse from the authorization server token endpoint
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param credentialFormats which credentials to request, picked out of
     * [IssuerMetadata.supportedCredentialConfigurations]
     * @param previouslyRequestedScope the `scope` value requested in the token request, since the authorization server
     * may not set it in [tokenResponse]
     */
    fun prepareCredentialRequests(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormats: Collection<SupportedCredentialFormat>,
        previouslyRequestedScope: String? = null,
    ): KmmResult<Collection<PreparedCredentialRequest>> = catching {
        prepareInternal(tokenResponse, previouslyRequestedScope, metadata, credentialFormats)
            .ifEmpty { throw InvalidToken("Token response grants none of the selected credentials") }
    }

    /**
     * Prepares the credential requests the access token of [tokenResponse] grants for all its credentials,
     * each with the configuration its proof and response depend on, still without proofs and
     * encryption. Create each request with its own `c_nonce` right before sending it with
     * [OpenId4VciProtocolClient.credentialRequest], which adds the access token from [tokenResponse] and, for
     * DPoP-bound tokens, the DPoP proof, and parses the response.
     *
     * @param tokenResponse from the authorization server token endpoint
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param previouslyRequestedScope the `scope` value requested in the token request, since the authorization server
     * may not set it in [tokenResponse]
     */
    fun prepareCredentialRequests(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        previouslyRequestedScope: String? = null,
    ): KmmResult<Collection<PreparedCredentialRequest>> = catching {
        prepareInternal(tokenResponse, previouslyRequestedScope, metadata, null)
            .ifEmpty { throw InvalidToken("Token response grants no credentials") }
    }

    private fun prepareInternal(
        tokenResponse: TokenResponseParameters,
        previouslyRequestedScope: String?,
        metadata: IssuerMetadata,
        credentialFormats: Collection<SupportedCredentialFormat>?
    ): Collection<PreparedCredentialRequest> {
        val authorizationDetails = tokenResponse.authorizationDetails
        val scope = tokenResponse.scope ?: previouslyRequestedScope
        val prepared = if (authorizationDetails != null) {
            authorizationDetails.filterIsInstance<OpenIdAuthorizationDetails>()
                .flatMap { it.toPreparedCredentialRequests(metadata, credentialFormats) }
        } else if (scope != null) {
            scope.split(" ").filter(String::isNotBlank).flatMap { singleScope ->
                metadata.supportedCredentialConfigurations
                    .filter { it.value.scope == singleScope && (credentialFormats == null || it.value in credentialFormats) }
                    .keys
            }.distinct().map {
                PreparedCredentialRequest(
                    credentialConfigurationId = it,
                    credentialRequestParameters = CredentialRequestParameters(credentialConfigurationId = it),
                    credentialFormat = metadata.supportedCredentialConfigurations.getValue(it),
                )
            }
        } else {
            throw InvalidToken("Token response contains neither authorization_details nor scope")
        }
        return prepared
    }

    /**
     * Prepares one credential request per entry of [credentialConfigurationIds], each with its configuration from
     * [IssuerMetadata.supportedCredentialConfigurations] of [metadata], still without proofs and encryption, see
     * [createCredential].
     *
     * Only use this when the token response contained no `credential_identifiers` in its `authorization_details`,
     * because then the requests have to use those, and `credential_configuration_id` "MUST NOT be present"
     * (OpenID4VCI 1.0, 8.2). Otherwise, use the overload accepting [TokenResponseParameters].
     *
     * Fails for an identifier that [metadata] does not list.
     *
     * @param credentialConfigurationIds the exact `credential_configuration_id`s to request, keys of
     * [IssuerMetadata.supportedCredentialConfigurations]
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     */
    fun prepareCredentialRequests(
        credentialConfigurationIds: Set<String>,
        metadata: IssuerMetadata,
    ): KmmResult<Collection<PreparedCredentialRequest>> = catching {
        credentialConfigurationIds.map {
            PreparedCredentialRequest(
                credentialConfigurationId = it,
                credentialRequestParameters = CredentialRequestParameters(credentialConfigurationId = it),
                credentialFormat = metadata.supportedCredentialConfigurations[it]
                    ?: throw UnknownCredentialConfiguration(it),
            )
        }
    }

    /**
     * The credential requests these authorization details of a token response grant, if [credentialFormats] contains
     * the configuration of their `credential_configuration_id`, which is REQUIRED (OpenID4VCI 1.0, 5.1.1): one per
     * `credential_identifier` of that configuration (6.2), sent without the `credential_configuration_id`, which
     * "MUST NOT be present" then (8.2), or else one for the `credential_configuration_id`.
     */
    private fun OpenIdAuthorizationDetails.toPreparedCredentialRequests(
        metadata: IssuerMetadata,
        credentialFormats: Collection<SupportedCredentialFormat>?,
    ): Collection<PreparedCredentialRequest> {
        val configurationId = credentialConfigurationId?.takeIf { it.isNotEmpty() }
            ?: throw InvalidToken("Authorization details contain no credential_configuration_id")
        val format = metadata.supportedCredentialConfigurations[configurationId]
            ?.takeIf { credentialFormats == null || it in credentialFormats }
            ?: return listOf()
        val parameters = credentialIdentifiers?.takeIf { it.isNotEmpty() }
            ?.map { CredentialRequestParameters(credentialIdentifier = it) }
            ?: listOf(CredentialRequestParameters(credentialConfigurationId = configurationId))
        return parameters.map { PreparedCredentialRequest(configurationId, it, format) }
    }

    /**
     * Creates the credential request to be sent to the credential issuer.
     * Send each request with [OpenId4VciProtocolClient.credentialRequest], which adds the access token from
     * [tokenResponse] and, for DPoP-bound tokens, the DPoP proof, and parses the response.
     *
     * Creates all requests with the same [clientNonce]. With a credential issuer that accepts each `c_nonce` only once,
     * use [prepareCredentialRequests], and create each request with its own `c_nonce` with the overload accepting a
     * [PreparedCredentialRequest] instead.
     *
     * @param tokenResponse from the authorization server token endpoint
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param credentialFormat which credential to request (needed to build the correct proof)
     * @param clientNonce if required by the issuer (see [IssuerMetadata.nonceEndpointUrl]),
     * the value from there, exactly [ClientNonceResponse.clientNonce]
     * @param previouslyRequestedScope the `scope` value requested in the token request, since the authorization server
     * may not set it in [tokenResponse]
     * @param clientId the `client_id` of the OAuth 2.0 client, used as the issuer of proof JWTs
     */
    suspend fun createCredential(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clientId: String = defaultClientId,
    ): KmmResult<Collection<CredentialRequest>> = catching {
        prepareCredentialRequests(
            tokenResponse = tokenResponse,
            metadata = metadata,
            credentialFormats = setOf(credentialFormat),
            previouslyRequestedScope = previouslyRequestedScope
        ).getOrThrow().map {
            it.withProofAndEncryption(metadata, clientNonce, clientId)
        }.map { (parameters, proofKeys) ->
            encryptionService.wrapCredentialRequest(parameters, metadata, proofKeys.toSet()).getOrThrow()
        }
    }

    /**
     * Creates the credential request for exactly one credential, to be sent to the credential issuer.
     * Send it with [OpenId4VciProtocolClient.credentialRequest], which adds the access token and, for DPoP-bound
     * tokens, the DPoP proof, and parses the response.
     *
     * Only use this when the token response did not contain `credential_identifiers` in its
     * `authorization_details`, because then `credential_configuration_id` MUST NOT be used (OID4VCI 1.0 Section 8.2),
     * see [CredentialRequestParameters.credentialConfigurationId].
     * Otherwise, use the overload accepting [TokenResponseParameters].
     *
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param credentialConfigurationId the exact `credential_configuration_id` to request, one of the keys from
     * [IssuerMetadata.supportedCredentialConfigurations]
     * @param clientNonce if required by the issuer (see [IssuerMetadata.nonceEndpointUrl]),
     * the value from there, exactly [ClientNonceResponse.clientNonce]
     * @param clientId the `client_id` of the OAuth 2.0 client, used as the issuer of proof JWTs
     */
    suspend fun createCredential(
        metadata: IssuerMetadata,
        credentialConfigurationId: String,
        clientNonce: String? = null,
        clientId: String = defaultClientId,
    ): KmmResult<CredentialRequest> = catching {
        createCredential(
            request = prepareCredentialRequests(setOf(credentialConfigurationId), metadata).getOrThrow().single(),
            metadata = metadata,
            clientNonce = clientNonce,
            clientId = clientId,
        ).getOrThrow()
    }

    /**
     * Creates the credential request for [request], prepared with [prepareCredentialRequests], with a proof for its
     * [PreparedCredentialRequest.credentialFormat] (see [ProofCreator]) and, if the credential issuer supports it, the
     * encryption of request and response (OpenID4VCI 1.0, 10). Create it right before sending it with
     * [OpenId4VciProtocolClient.credentialRequest], each with a fresh [clientNonce], as the credential issuer decides
     * how long a `c_nonce` can be used (13.8), and may accept each one only once.
     *
     * @param request one of the requests from [prepareCredentialRequests]
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param clientNonce if required by the issuer (see [IssuerMetadata.nonceEndpointUrl]),
     * the value from there, exactly [ClientNonceResponse.clientNonce]
     * @param clientId the `client_id` of the OAuth 2.0 client, used as the issuer of proof JWTs
     */
    suspend fun createCredential(
        request: PreparedCredentialRequest,
        metadata: IssuerMetadata,
        clientNonce: String? = null,
        clientId: String = defaultClientId,
    ): KmmResult<CredentialRequest> = catching {
        val (parameters, proofKeys) = request.withProofAndEncryption(metadata, clientNonce, clientId)
        encryptionService.wrapCredentialRequest(parameters, metadata, proofKeys.toSet()).getOrThrow()
    }

    /** The parameters with a proof, created anew for every request, and the key the proof proves or attests. */
    private suspend fun PreparedCredentialRequest.withProofAndEncryption(
        metadata: IssuerMetadata,
        clientNonce: String?,
        clientId: String,
    ): Pair<CredentialRequestParameters, List<CryptoPublicKey>> {
        val proof = createCredentialProof(metadata, credentialFormat, clientId, clientNonce)
        return credentialRequestParameters.copy(
            proofs = proof?.proofs,
            credentialResponseEncryption = encryptionService.credentialResponseEncryption(metadata)
        ) to listOfNotNull(proof?.key)
    }

    /**
     * The proof of the first of [proofCreators] that creates one for [credentialFormat]: the request carries exactly
     * one proof type (OpenID4VCI 1.0, 8.2), and the issuer accepts each of its `proof_types_supported`, so a creator
     * that fails, e.g. as it can not load a required key attestation, leaves it to the next one.
     *
     * Fails with the failure of the first creator if none creates a proof, although the issuer lists proof types,
     * because then `proofs` "MUST be present" (8.2). Without `proof_types_supported`, "the Wallet is not required to
     * supply proofs" (12.2.4), so there is none.
     *
     * Fails at once if a creator fails because the user cancelled the signature, e.g. unlocking the key: the next
     * creator would create a proof the user has just declined, with a new key.
     */
    @Throws(Exception::class, CancellationException::class)
    internal suspend fun createCredentialProof(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientId: String,
        clientNonce: String?
    ): CreatedProof? {
        val failures = mutableListOf<Throwable>()
        proofCreators.forEach { creator ->
            val result = creator.createProof(
                credentialIssuer = metadata.credentialIssuer,
                credentialFormat = credentialFormat,
                clientId = clientId,
                clientNonce = clientNonce,
            )
            result.getOrNull()?.let { return it }
            result.exceptionOrNull()?.let { failure ->
                failure.getUserSignatureCancellationException()?.let { throw it }
                failures += failure
            }
        }
        val requiredProofTypes = credentialFormat.supportedProofTypes?.keys
        if (requiredProofTypes.isNullOrEmpty())
            return null
        throw failures.firstOrNull()
            ?.also { first -> failures.drop(1).forEach { first.addSuppressed(it) } }
            ?: IllegalArgumentException("No proof creator for the supported proof types $requiredProofTypes")
    }

    /**
     * Decodes [response] received from the credential issuer like [decodeCredentialResponse], reading it as a compact
     * JWE if [isEncrypted], i.e. if its media type is `application/jwt`.
     */
    suspend fun decodeCredentialResponse(
        response: String,
        isEncrypted: Boolean,
        request: CredentialRequest,
        representation: CredentialRepresentation,
    ): KmmResult<Collection<ReceivedCredential>> = catching {
        decodeCredentialResponse(
            response = response.toCredentialResponse(isEncrypted),
            request = request,
            representation = representation
        ).getOrThrow()
    }

    /**
     * Decodes [response] received from the credential issuer for [request] into one [ReceivedCredential] per
     * credential, encoded in [representation], also for one that can not be decoded, so that no member of a batch goes
     * unnoticed.
     * Validates nothing: prepare the storage of each one with [ReceivedCredential.prepareCredentialStorage], which
     * validates it with the holder's key and validator.
     *
     * Fails only for the response itself: if it is not encrypted exactly when [request] asked for an encrypted
     * response, or if it can not be decrypted.
     */
    suspend fun decodeCredentialResponse(
        response: CredentialResponse,
        request: CredentialRequest,
        representation: CredentialRepresentation,
    ): KmmResult<Collection<ReceivedCredential>> = catching {
        decryptCredentialResponse(response, request).credentials.orEmpty().map { credential ->
            catchingUnwrapped {
                credential.credentialString?.toValidationInput(representation)
                    ?: throw IllegalArgumentException("Credential is not a string (OpenID4VCI 1.0, Appendix A)")
            }.fold(
                onSuccess = { ReceivedCredential.Decoded(it, request.proofKeys) },
                onFailure = { ReceivedCredential.Undecodable(it) },
            )
        }
    }

    @Throws(Exception::class)
    private suspend fun decryptCredentialResponse(
        response: CredentialResponse,
        request: CredentialRequest,
    ): CredentialResponseParameters {
        request.validateResponseEncryption(response is CredentialResponse.Encrypted)
        return when (response) {
            is CredentialResponse.Plain -> response.response
            is CredentialResponse.Encrypted -> encryptionService.decryptToCredentialResponse(
                response.response,
                request.credentialResponseEncryptionKeyId.shouldBePresent(),
            ).getOrThrow()
        }
    }

    /** Reads [this] as the body of a credential response, which is a compact JWE if [isEncrypted]. */
    @Throws(Exception::class)
    private fun String.toCredentialResponse(isEncrypted: Boolean): CredentialResponse =
        if (isEncrypted) {
            if (count { it == '.' } != 4)
                throw InvalidEncryptionParameters("Parsing of JWE failed, not five parts")
            CredentialResponse.Encrypted(JweEncrypted.deserialize(this).getOrElse {
                throw InvalidEncryptionParameters("Parsing of JWE failed", it)
            })
        } else CredentialResponse.Plain(joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(this))

    private fun CredentialRequest.validateResponseEncryption(isEncrypted: Boolean) {
        val expectedEncrypted = credentialResponseEncryptionKeyId != null
        if (expectedEncrypted != isEncrypted)
            throw InvalidEncryptionParameters(
                if (expectedEncrypted) "Credential response was not encrypted as requested"
                else "Credential response was encrypted without being requested"
            )
    }

    private fun String?.shouldBePresent(): String =
        this ?: throw InvalidEncryptionParameters("Credential request contains no response encryption key id")

    /** An mdoc is the base64url encoding of its CBOR-encoded `IssuerSigned` (OpenID4VCI 1.0, A.2.4). */
    @Throws(Exception::class)
    private fun String.toValidationInput(representation: CredentialRepresentation): CredentialValidationInput =
        when (representation) {
            PLAIN_JWT -> CredentialValidationInput.VcJwt(this)
            SD_JWT -> CredentialValidationInput.SdJwtVc(this)
            ISO_MDOC -> CredentialValidationInput.IsoMdoc(decodeToByteArray(Base64UrlStrict))
        }

}
