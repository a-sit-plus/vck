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
import at.asitplus.iso.IssuerSigned
import at.asitplus.openid.AuthorizationDetails
import at.asitplus.openid.ClientNonceResponse
import at.asitplus.openid.CredentialOffer
import at.asitplus.openid.CredentialOfferUrlParameters
import at.asitplus.openid.CredentialRequestParameters
import at.asitplus.openid.CredentialRequestProofContainer
import at.asitplus.openid.CredentialResponseParameters
import at.asitplus.openid.IssuerMetadata
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJsonLd
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwtJsonLd
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.openid.decodeFromQuery
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JweEncrypted
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.KeyAttestationJwt
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.RemoteResourceRetrieverFunction
import at.asitplus.wallet.lib.RemoteResourceRetrieverInput
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Holder.StoreCredentialInput.*
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.*
import at.asitplus.wallet.lib.data.CredentialRepresentation
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.*
import at.asitplus.wallet.lib.oidvci.OpenId4VciServer.CredentialResponse
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.decodeFromJsonElement
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration

@Deprecated("Renamed", ReplaceWith("OpenId4VciClient"))
typealias WalletService = OpenId4VciClient

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
    /**
     * Only used by the deprecated [parseCredentialOffer], to retrieve the resource referenced by
     * `credential_offer_uri`; use [OpenId4VciProtocolClient.loadCredentialOffer] instead.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /** Handles credential request encryption and credential response decryption. */
    private val encryptionService: WalletEncryptionService = WalletEncryptionService(),
    /** First one to create a proof for a given credential is selected for the [CredentialRequestParameters]. */
    private val proofCreators: List<ProofCreator>,
) {

    @Deprecated("Use constructor with proofCreators")
    @JvmOverloads
    constructor(
        /**
         * Used as the issuer in credential proofs when [createCredential] gets no `clientId`. Deprecated, as the `client_id`
         * belongs to the OAuth 2.0 client: [OpenId4VciProtocolClient.createCredential] passes the one of its [OAuth2Client].
         */
        clientId: String = "https://wallet.a-sit.at/app",
        /** Used to prove possession of the key material for [CredentialRequestProofContainer], i.e., the holder key. */
        keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
        /**
         * Only used by the deprecated [parseCredentialOffer], to retrieve the resource referenced by
         * `credential_offer_uri`; use [OpenId4VciProtocolClient.loadCredentialOffer] instead.
         */
        remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
        /** Handles credential request encryption and credential response decryption. */
        encryptionService: WalletEncryptionService = WalletEncryptionService(),
        loadKeyAttestation: (suspend (KeyAttestationInput) -> KmmResult<JwsCompactTyped<KeyAttestationJwt>>)? = null,
        /**
         * Selects the key binding to embed in the [JwsHeader] of a credential request proof JWT,
         * as defined in the OpenID for Verifiable Credential Issuance specification.
         *
         * This function determines how the holder's key is referenced in the proof JWT header,
         * by selecting between two mutually exclusive binding mechanisms:
         *
         * - **`jwk`** ([JwsHeader.jsonWebKey]): embeds the [JsonWebKey] inline in the header,
         *   suitable when the holder has no associated DID.
         * - **`kid`** ([JwsHeader.keyId]): embeds a DID URL string in the header,
         *   identifying a specific key within the holder's DID Document.
         *
         * The lambda receives the current [KeyMaterial] and must return a [Pair] where:
         * - the **first** element is the [JsonWebKey] to embed as the `jwk` header parameter, or `null`,
         * - the **second** element is the DID URL string to embed as the `kid` header parameter, or `null`.
         *
         * Exactly **one** of the two values must be non-null, as `jwk` and `kid` are mutually exclusive:
         * - Returning **both non-null** will throw an [IllegalArgumentException] during proof creation.
         * - Returning **both null** will throw an [IllegalArgumentException] during proof creation.
         *
         * Defaults to selecting the [JsonWebKey] from [KeyMaterial.jsonWebKey] as the `jwk` binding,
         * which is suitable when no DID is associated with the holder.
         *
         * @see JwsHeader.jsonWebKey
         * @see JwsHeader.keyId
         */
        selectProofJwtKeyBinding: (suspend (KeyMaterial) -> Pair<JsonWebKey?, String?>) = { key ->
            Pair(key.jsonWebKey, null)
        },
        /** Clock to use for proof generation. */
        clock: Clock = Clock.System,
    ) : this(
        clientId = clientId,
        remoteResourceRetriever = remoteResourceRetriever,
        encryptionService = encryptionService,
        proofCreators = listOfNotNull(
            JwtProofCreator(keyMaterial, loadKeyAttestation, selectProofJwtKeyBinding, clock),
            loadKeyAttestation?.let { AttestationProofCreator(it) },
        )
    )

    private val defaultClientId = clientId

    @Deprecated(
        "The client ID belongs to the OAuth 2.0 client: use OAuth2Client.clientId, which " +
                "OpenId4VciProtocolClient.createCredential passes to createCredential",
    )
    val clientId: String
        get() = defaultClientId

    data class KeyAttestationInput(
        val credentialIssuer: String?,
        val clientNonce: String?,
        val supportedAlgorithms: Collection<String>?,
        val preferredKeyStorageStatusPeriod: Duration?,
    )

    sealed interface CredentialRequest {
        /** `kid` of the key this request advertised for encrypting its response, if any. */
        val credentialResponseEncryptionKeyId: String?

        /**
         * Send [request] as JSON-serialized content to the server at [IssuerMetadata.credentialEndpointUrl] with media
         * type `application/json` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JSON]).
         */
        data class Plain(val request: CredentialRequestParameters) : CredentialRequest {
            override val credentialResponseEncryptionKeyId: String?
                get() = request.credentialResponseEncryption?.jsonWebKey?.keyId
        }

        /**
         * Send [request] as JWE-serialized content to the server at [IssuerMetadata.credentialEndpointUrl] with media
         * type `application/jwt` (see [at.asitplus.wallet.lib.data.MediaTypes.Application.JWT]).
         */
        data class Encrypted(
            val request: JweEncrypted,
            override val credentialResponseEncryptionKeyId: String? = null,
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

    /**
     * Parses [input] as either a JSON-encoded [CredentialOffer] or a credential offer URL.
     *
     * A credential offer URL may contain an embedded `credential_offer` or a `credential_offer_uri`.
     * Resources referenced by `credential_offer_uri` are retrieved with [remoteResourceRetriever] and parsed.
     */
    @Deprecated(
        "Retrieving a credential offer by reference is a request to the credential issuer: use " +
                "OpenId4VciProtocolClient.loadCredentialOffer, or OpenId4VciClient.loadCredentialOffer with ktor",
    )
    suspend fun parseCredentialOffer(input: String): KmmResult<CredentialOffer> = catching {
        when (val parsed = parseCredentialOfferInput(input)) {
            is CredentialOfferInput.ByValue -> parsed.offer
            is CredentialOfferInput.ByReference -> {
                val response = remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(parsed.uri))
                    ?: throw InvalidRequest("credential offer retrieval returned no response")
                @Suppress("DEPRECATION")
                parseCredentialOffer(response).getOrThrow()
            }
        }
    }

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
     * Creates the credential request to be sent to the credential issuer.
     * Send each request with [OpenId4VciProtocolClient.credentialRequest], which adds the access token from
     * [tokenResponse] and, for DPoP-bound tokens, the DPoP proof, and parses the response.
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
        createCredentialRequestInternal(
            tokenResponse = tokenResponse,
            metadata = metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
            previouslyRequestedScope = previouslyRequestedScope,
            clientId = clientId,
        ).getOrThrow().map {
            encryptionService.wrapCredentialRequest(it, metadata).getOrThrow()
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
        val credentialFormat = metadata.supportedCredentialConfigurations[credentialConfigurationId]
            ?: throw UnknownCredentialConfiguration(credentialConfigurationId)
        CredentialRequestParameters(credentialConfigurationId = credentialConfigurationId)
            .withProofAndEncryption(metadata, credentialFormat, clientNonce, clientId)
            .also { Napier.i("createCredentialRequest returns $it") }
            .let { encryptionService.wrapCredentialRequest(it, metadata).getOrThrow() }
    }

    private suspend fun createCredentialRequestInternal(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clientId: String,
    ): KmmResult<Collection<CredentialRequestParameters>> = catching {
        tokenResponse.toCredentialRequestParameters(metadata, credentialFormat, previouslyRequestedScope)
            .map { it.withProofAndEncryption(metadata, credentialFormat, clientNonce, clientId) }
            .also { Napier.i("createCredentialRequest returns $it") }
    }

    private suspend fun CredentialRequestParameters.withProofAndEncryption(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String?,
        clientId: String,
    ): CredentialRequestParameters = copy(
        proofs = createCredentialProof(metadata, credentialFormat, clientId, clientNonce),
        credentialResponseEncryption = encryptionService.credentialResponseEncryption(metadata)
    )

    /**
     * The proof of the first of [proofCreators] that creates one for [credentialFormat]: the request carries exactly
     * one proof type (OpenID4VCI 1.0, 8.2), and the issuer accepts each of its `proof_types_supported`, so a creator
     * that fails, e.g. as it can not load a required key attestation, leaves it to the next one.
     *
     * Fails with the failure of the first creator if none creates a proof, although the issuer lists proof types,
     * because then `proofs` "MUST be present" (8.2). Without `proof_types_supported`, "the Wallet is not required to
     * supply proofs" (12.2.4), so there is none.
     */
    @Throws(Exception::class, CancellationException::class)
    internal suspend fun createCredentialProof(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientId: String,
        clientNonce: String?
    ): CredentialRequestProofContainer? {
        val failures = mutableListOf<Throwable>()
        proofCreators.forEach { creator ->
            val result = creator.invoke(
                credentialIssuer = metadata.credentialIssuer,
                credentialFormat = credentialFormat,
                clientId = clientId,
                clientNonce = clientNonce
            )
            result.getOrNull()?.let { return it }
            result.exceptionOrNull()?.let { failures += it }
        }
        val requiredProofTypes = credentialFormat.supportedProofTypes?.keys
        if (requiredProofTypes.isNullOrEmpty())
            return null
        throw failures.firstOrNull()
            ?.also { first -> failures.drop(1).forEach { first.addSuppressed(it) } }
            ?: IllegalArgumentException("No proof creator for the supported proof types $requiredProofTypes")
    }

    private fun TokenResponseParameters.toCredentialRequestParameters(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        previouslyRequestedScope: String?
    ): Collection<CredentialRequestParameters> = if (authorizationDetails != null) {
        authorizationDetails!!.toCredentialRequestParameters()
    } else if (scope != null) {
        scope!!.mapScopeToCredentialRequestParameters(metadata, credentialFormat)
    } else if (previouslyRequestedScope != null) {
        previouslyRequestedScope.mapScopeToCredentialRequestParameters(metadata, credentialFormat)
    } else {
        throw InvalidToken("Can't parse token: $this")
    }

    /**
     * Parses [response] received from the credential issuer, mapping to [Holder.StoreCredentialInput],
     * rejecting encrypted responses because they require the originating [CredentialRequest].
     */
    @Deprecated(
        "Without the originating credential request, a plain response is accepted even if the request asked for an " +
                "encrypted one: pass the CredentialRequest to decodeCredentialResponse, and prepare the storage of " +
                "each ReceivedCredential with ReceivedCredential.prepareCredentialStorage, which validates it",
    )
    suspend fun parseCredentialResponse(
        response: String,
        isEncrypted: Boolean,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        @Suppress("DEPRECATION")
        parseCredentialResponse(
            response = response.toCredentialResponse(isEncrypted),
            representation = representation,
            scheme = scheme
        ).getOrThrow()
    }

    /** Parses a response and binds its encryption to the exact [request] that caused it. */
    @Deprecated(
        "Decodes the credentials without validating them: decode them with decodeCredentialResponse, and prepare " +
                "the storage of each ReceivedCredential with ReceivedCredential.prepareCredentialStorage, which " +
                "validates it",
    )
    suspend fun parseCredentialResponse(
        response: String,
        isEncrypted: Boolean,
        request: CredentialRequest,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        @Suppress("DEPRECATION")
        parseCredentialResponse(
            response = response.toCredentialResponse(isEncrypted),
            request = request,
            representation = representation,
            scheme = scheme
        ).getOrThrow()
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
    ): KmmResult<List<ReceivedCredential>> = catching {
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
    ): KmmResult<List<ReceivedCredential>> = catching {
        decryptCredentialResponse(response, request).credentials.orEmpty().map { credential ->
            catchingUnwrapped {
                credential.credentialString?.toValidationInput(representation)
                    ?: throw IllegalArgumentException("Credential is not a string (OpenID4VCI 1.0, Appendix A)")
            }.fold(
                onSuccess = { ReceivedCredential.Decoded(it) },
                onFailure = { ReceivedCredential.Undecodable(it) },
            )
        }
    }

    /**
     * Parses [response] received from the credential issuer, mapping to [Holder.StoreCredentialInput],
     * rejecting encrypted responses because they require the originating [CredentialRequest].
     */
    @Deprecated(
        "Without the originating credential request, a plain response is accepted even if the request asked for an " +
                "encrypted one: pass the CredentialRequest to decodeCredentialResponse, and prepare the storage of " +
                "each ReceivedCredential with ReceivedCredential.prepareCredentialStorage, which validates it",
    )
    suspend fun parseCredentialResponse(
        response: CredentialResponse,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        if (response is CredentialResponse.Encrypted)
            throw InvalidEncryptionParameters("Originating credential request required for encrypted response")
        (response as CredentialResponse.Plain).response
            .extractCredentials()
            .map { it.toStoreCredentialInput(representation, scheme) }
    }

    /** Parses a response and binds its encryption to the exact [request] that caused it. */
    @Deprecated(
        "Decodes the credentials without validating them: decode them with decodeCredentialResponse, and prepare " +
                "the storage of each ReceivedCredential with ReceivedCredential.prepareCredentialStorage, which " +
                "validates it",
    )
    suspend fun parseCredentialResponse(
        response: CredentialResponse,
        request: CredentialRequest,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        decryptCredentialResponse(response, request)
            .extractCredentials().map { it.toStoreCredentialInput(representation, scheme) }
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

    private fun Set<AuthorizationDetails>.toCredentialRequestParameters(): List<CredentialRequestParameters> =
        filterIsInstance<OpenIdAuthorizationDetails>().flatMap {
            if (it.credentialIdentifiers != null && it.credentialIdentifiers?.isNotEmpty() == true) {
                it.credentialIdentifiers!!.map { CredentialRequestParameters(credentialIdentifier = it) }
            } else if (it.credentialConfigurationId != null && it.credentialConfigurationId?.isNotEmpty() == true) {
                listOf(CredentialRequestParameters(credentialConfigurationId = it.credentialConfigurationId!!))
            } else throw InvalidToken("Invalid authorization details: $it")
        }

    private fun String.mapScopeToCredentialRequestParameters(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
    ): Set<CredentialRequestParameters> = mapScopeToCredentialConfigurationIds(metadata, credentialFormat)
        .map { CredentialRequestParameters(credentialConfigurationId = it) }
        .toSet()

    private fun String.mapScopeToCredentialConfigurationIds(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
    ): Set<String> {
        if (credentialFormat.scope == null)
            throw UnknownCredentialConfiguration("Credential does not support scope: $credentialFormat")
        val scopes = split(" ").filter(String::isNotBlank)
        if (credentialFormat.scope !in scopes)
            throw UnknownCredentialConfiguration(this)
        return scopes.mapNotNull { singleScope ->
            metadata.supportedCredentialConfigurations.entries
                .firstOrNull { it.value.scope == singleScope && it.value.format == credentialFormat.format }
                ?.key
        }.toSet().ifEmpty {
            throw UnknownCredentialConfiguration(this)
        }
    }

    /** An mdoc is the base64url encoding of its CBOR-encoded `IssuerSigned` (OpenID4VCI 1.0, A.2.4). */
    @Throws(Exception::class)
    private fun String.toValidationInput(representation: CredentialRepresentation): CredentialValidationInput =
        when (representation) {
            PLAIN_JWT -> CredentialValidationInput.VcJwt(this)
            SD_JWT -> CredentialValidationInput.SdJwtVc(this)
            ISO_MDOC -> CredentialValidationInput.IsoMdoc(decodeToByteArray(Base64UrlStrict))
        }

    /** An mdoc is the base64url encoding of its CBOR-encoded `IssuerSigned` (OpenID4VCI 1.0, A.2.4). */
    @Throws(Exception::class)
    private fun String.toStoreCredentialInput(
        credentialRepresentation: CredentialRepresentation,
        credentialScheme: CredentialScheme,
    ): Holder.StoreCredentialInput = when (credentialRepresentation) {
        PLAIN_JWT -> Vc(
            signedVcJws = JwsCompactTyped<VerifiableCredentialJws>(this),
            vcJws = this,
            scheme = credentialScheme as VcJwtCredentialScheme
        )

        SD_JWT -> SdJwt(
            signedSdJwtVc = SdJwtSigned.parseCatching(this).getOrThrow(),
            vcSdJwt = this,
            scheme = credentialScheme as SdJwtCredentialScheme
        )

        ISO_MDOC -> catchingUnwrapped {
            Iso(
                issuerSigned = coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(
                    decodeToByteArray(Base64UrlStrict)
                ),
                scheme = credentialScheme as IsoMdocCredentialScheme
            )
        }.getOrElse { throw Exception("Invalid credential format: $this", it) }
    }
}
