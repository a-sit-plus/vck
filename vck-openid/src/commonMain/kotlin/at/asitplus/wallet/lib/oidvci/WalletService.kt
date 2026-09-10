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
import at.asitplus.openid.KeyAttestationRequired
import at.asitplus.openid.OpenIdAuthorizationDetails
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ProofTypes
import at.asitplus.openid.SupportedCredentialFormat
import at.asitplus.openid.SupportedCredentialFormatIsoMdoc
import at.asitplus.openid.SupportedCredentialFormatSdJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJsonLd
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwt
import at.asitplus.openid.SupportedCredentialFormatW3cVcJwtJsonLd
import at.asitplus.openid.TokenResponseParameters
import at.asitplus.openid.truncateToSeconds
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JsonWebToken
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
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.oauth2.OAuth2Client
import at.asitplus.wallet.lib.oidvci.CredentialIssuer.CredentialResponse
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidEncryptionParameters
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidRequest
import at.asitplus.wallet.lib.oidvci.OAuth2Exception.InvalidToken
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.ktor.util.*
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.json.decodeFromJsonElement
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock
import kotlin.time.Duration

/**
 * Client service to retrieve credentials using OID4VCI
 *
 * Implemented from
 * [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 * 1.0 from 2025-09-16.
 */
class WalletService @JvmOverloads constructor(
    /** Used as the issuer in credential proofs. Must match the `client_id` of the OAuth client. */
    val clientId: String = "https://wallet.a-sit.at/app",
    /** Used to prove possession of the key material for [CredentialRequestProofContainer], i.e., the holder key. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /**
     * Need to implement if resources are defined by reference, i.e. the URL for a [JsonWebKeySet],
     * or the authentication request itself as `request_uri`, or `presentation_definition_uri`.
     * Implementations need to fetch the url passed in, and return either the body, if there is one,
     * or the HTTP header `Location`, i.e. if the server sends the request object as a redirect.
     */
    private val remoteResourceRetriever: RemoteResourceRetrieverFunction = { null },
    /** Handles credential request encryption and credential response decryption. */
    private val encryptionService: WalletEncryptionService = WalletEncryptionService(),
    private val loadKeyAttestation: (suspend (KeyAttestationInput) -> KmmResult<JwsCompactTyped<KeyAttestationJwt>>)? = null,
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
    private val selectProofJwtKeyBinding: (suspend (KeyMaterial) -> Pair<JsonWebKey?, String?>) = { key ->
        Pair(key.jsonWebKey, null)
    }
) {

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
     * Pass in the URL provided by the Credential Issuer,
     * which may contain a direct [CredentialOffer] or a URI pointing to it.
     */
    suspend fun parseCredentialOffer(input: String): KmmResult<CredentialOffer> = catching {
        if (input.trimStart().startsWith("{")) {
            catchingUnwrapped {
                joseCompliantSerializer.decodeFromString<CredentialOffer>(input)
            }.getOrElse {
                throw InvalidRequest("could not parse credential offer", it)
            }
        } else {
            val parameters = catchingUnwrapped { input.extractParams() }.getOrElse {
                throw InvalidRequest("could not parse credential offer URL", it)
            }
            parameters.fetchCredentialOffer()
        }
    }

    private fun String.extractParams(): CredentialOfferUrlParameters =
        Url(this).parameters.flattenEntries().toMap().decodeFromUrlQuery<CredentialOfferUrlParameters>()

    private suspend fun CredentialOfferUrlParameters.fetchCredentialOffer(): CredentialOffer {
        credentialOffer?.let { offer ->
            return catchingUnwrapped {
                joseCompliantSerializer.decodeFromJsonElement<CredentialOffer>(offer)
            }.getOrElse {
                throw InvalidRequest("could not parse embedded credential offer", it)
            }
        }
        val uri = credentialOfferUrl
            ?: throw InvalidRequest("credential offer URL contains neither credential_offer nor credential_offer_uri")
        val response = remoteResourceRetriever.invoke(RemoteResourceRetrieverInput(uri))
            ?: throw InvalidRequest("credential offer retrieval returned no response")
        return parseCredentialOffer(response).getOrThrow()
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
    ) = buildAuthorizationDetails(setOf(credentialConfigurationId), authorizationServers)

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
    ) = credentialConfigurationIds.map {
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
    ) = metadata.supportedCredentialConfigurations?.values?.filter {
        it.format.toRepresentation() == requestOptions.representation
    }?.firstOrNull {
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
     * Also send along the [TokenResponseParameters.accessToken] from the token response in HTTP header `Authorization`
     * see [TokenResponseParameters.toHttpHeaderValue].
     * Be sure to include a DPoP header if [TokenResponseParameters.tokenType] is `DPoP`,
     * see [BuildDPoPHeader].
     * For sample ktor code see `OpenId4VciClient` in `vck-openid-ktor`.
     *
     * @param tokenResponse from the authorization server token endpoint
     * @param metadata the issuer's metadata, see [IssuerMetadata]
     * @param credentialFormat which credential to request (needed to build the correct proof)
     * @param clientNonce if required by the issuer (see [IssuerMetadata.nonceEndpointUrl]),
     * the value from there, exactly [ClientNonceResponse.clientNonce]
     * @param previouslyRequestedScope the `scope` value requested in the token request, since the authorization server
     * may not set it in [tokenResponse]
     */
    suspend fun createCredential(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<Collection<CredentialRequest>> = catching {
        createCredentialRequestInternal(
            tokenResponse = tokenResponse,
            metadata = metadata,
            credentialFormat = credentialFormat,
            clientNonce = clientNonce,
            previouslyRequestedScope = previouslyRequestedScope,
            clock = clock
        ).getOrThrow().map {
            encryptionService.wrapCredentialRequest(it, metadata).getOrThrow()
        }
    }

    private suspend fun createCredentialRequestInternal(
        tokenResponse: TokenResponseParameters,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String? = null,
        previouslyRequestedScope: String? = null,
        clock: Clock = Clock.System,
    ): KmmResult<Collection<CredentialRequestParameters>> = catching {
        val requests = if (tokenResponse.authorizationDetails != null) {
            tokenResponse.authorizationDetails!!.toCredentialRequest()
        } else if (tokenResponse.scope != null) {
            fromScopeToCredentialRequest(tokenResponse.scope!!, metadata, credentialFormat)
        } else if (previouslyRequestedScope != null) {
            fromScopeToCredentialRequest(previouslyRequestedScope, metadata, credentialFormat)
        } else {
            throw InvalidToken("Can't parse token: $tokenResponse")
        }
        requests.map {
            createCredentialRequestProof(
                metadata = metadata,
                credentialFormat = credentialFormat,
                clientNonce = clientNonce,
                clock = clock
            ).let { proof ->
                it.copy(
                    proofs = proof.takeIf { it.jwt != null || it.attestation != null },
                    credentialResponseEncryption = encryptionService.credentialResponseEncryption(metadata)
                )
            }
        }.also {
            Napier.i("createCredentialRequest returns $it")
        }
    }

    /**
     * Parses [response] received from the credential issuer, mapping to [Holder.StoreCredentialInput],
     * rejecting encrypted responses because they require the originating [CredentialRequest].
     */
    suspend fun parseCredentialResponse(
        response: String,
        isEncrypted: Boolean,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        if (isEncrypted)
            throw InvalidEncryptionParameters("Originating credential request required for encrypted response")
        joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(response)
            .extractCredentials()
            .map { it.toStoreCredentialInput(representation, scheme) }
    }

    /** Parses a response and binds its encryption to the exact [request] that caused it. */
    suspend fun parseCredentialResponse(
        response: String,
        isEncrypted: Boolean,
        request: CredentialRequest,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        request.validateResponseEncryption(isEncrypted)
        val responseParameters = if (isEncrypted)
            encryptionService.decryptToCredentialResponse(
                response,
                request.credentialResponseEncryptionKeyId.shouldBePresent(),
            ).getOrThrow()
        else joseCompliantSerializer.decodeFromString<CredentialResponseParameters>(response)
        responseParameters.extractCredentials().map { it.toStoreCredentialInput(representation, scheme) }
    }

    /**
     * Parses [response] received from the credential issuer, mapping to [Holder.StoreCredentialInput],
     * rejecting encrypted responses because they require the originating [CredentialRequest].
     */
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
    suspend fun parseCredentialResponse(
        response: CredentialResponse,
        request: CredentialRequest,
        representation: CredentialRepresentation,
        scheme: CredentialScheme,
    ): KmmResult<Collection<Holder.StoreCredentialInput>> = catching {
        val isEncrypted = response is CredentialResponse.Encrypted
        request.validateResponseEncryption(isEncrypted)
        when (response) {
            is CredentialResponse.Plain -> response.response
            is CredentialResponse.Encrypted -> encryptionService.decryptToCredentialResponse(
                response.response,
                request.credentialResponseEncryptionKeyId.shouldBePresent(),
            ).getOrThrow()
        }.extractCredentials().map { it.toStoreCredentialInput(representation, scheme) }
    }

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

    private fun Set<AuthorizationDetails>.toCredentialRequest(): List<CredentialRequestParameters> =
        filterIsInstance<OpenIdAuthorizationDetails>().flatMap {
            if (it.credentialIdentifiers != null && it.credentialIdentifiers?.isNotEmpty() == true) {
                it.credentialIdentifiers!!.map { CredentialRequestParameters(credentialIdentifier = it) }
            } else if (it.credentialConfigurationId != null && it.credentialConfigurationId?.isNotEmpty() == true) {
                listOf(CredentialRequestParameters(credentialConfigurationId = it.credentialConfigurationId!!))
            } else throw InvalidToken("Invalid authorization details: $it")
        }

    private fun fromScopeToCredentialRequest(
        scope: String,
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
    ): Set<CredentialRequestParameters> {
        if (credentialFormat.scope == null)
            throw OAuth2Exception.UnknownCredentialConfiguration("Credential does not support scope: $credentialFormat")
        if (!scope.trim().contains(credentialFormat.scope!!))
            throw OAuth2Exception.UnknownCredentialConfiguration(scope)
        return scope.split(" ").mapNotNull { singleScope ->
            metadata.supportedCredentialConfigurations
                ?.entries?.firstOrNull { it.value.scope == singleScope && it.value.format == credentialFormat.format }
                ?.key
                ?.let { CredentialRequestParameters(credentialConfigurationId = it) }
        }.toSet().ifEmpty {
            throw OAuth2Exception.UnknownCredentialConfiguration(scope)
        }
    }

    internal suspend fun createCredentialRequestProof(
        metadata: IssuerMetadata,
        credentialFormat: SupportedCredentialFormat,
        clientNonce: String?,
        clock: Clock = Clock.System,
    ): CredentialRequestProofContainer = credentialFormat.supportedProofTypes?.get(ProofTypes.JWT)?.let { type ->
        createCredentialRequestProofJwt(
            clientNonce = clientNonce,
            credentialIssuer = metadata.credentialIssuer,
            clock = clock,
            keyAttestationRequired = type.keyAttestationRequired,
            supportedAlgorithms = type.supportedSigningAlgorithms,
        )
    } ?: credentialFormat.supportedProofTypes?.get(ProofTypes.ATTESTATION)?.let { type ->
        createCredentialRequestProofAttestation(
            clientNonce = clientNonce,
            credentialIssuer = metadata.credentialIssuer,
            keyAttestationRequired = type.keyAttestationRequired,
            supportedAlgorithms = type.supportedSigningAlgorithms,
        )
    } ?: CredentialRequestProofContainer()

    internal suspend fun createCredentialRequestProofJwt(
        clientNonce: String?,
        credentialIssuer: String?,
        clock: Clock = Clock.System,
        keyAttestationRequired: KeyAttestationRequired? = null,
        supportedAlgorithms: Collection<String>? = null,
    ): CredentialRequestProofContainer {
        if (keyAttestationRequired != null && loadKeyAttestation == null) {
            throw IllegalArgumentException("Key attestation required, none provided")
        }
        val keyAttestation: JwsCompactTyped<KeyAttestationJwt>? = if (keyAttestationRequired != null) {
            loadKeyAttestation?.invoke(
                KeyAttestationInput(
                    credentialIssuer = credentialIssuer,
                    clientNonce = clientNonce,
                    supportedAlgorithms = supportedAlgorithms,
                    preferredKeyStorageStatusPeriod = keyAttestationRequired.preferredTtl,
                )
            )?.getOrElse { throw IllegalArgumentException("Key attestation required, none provided", it) }
        } else null
        keyAttestation?.requireKeyMaterialAtAttestedKeyIndex0()

        return CredentialRequestProofContainer(
            jwt = setOf(
                SignJwt<JsonWebToken>(
                    keyMaterial
                )
                // To be refactored once signJwt is not passed in the constructor but to this function
                { header: JwsHeader, key: KeyMaterial ->
                    val (jsonWebKey, keyId) = this.selectProofJwtKeyBinding.invoke(key)

                    when {
                        jsonWebKey != null && keyId.isNullOrEmpty() ->
                            header.copy(jsonWebKey = jsonWebKey, keyAttestation = keyAttestation?.jws)

                        jsonWebKey == null && !keyId.isNullOrEmpty() ->
                            header.copy(keyId = keyId, keyAttestation = keyAttestation?.jws)

                        jsonWebKey != null && !keyId.isNullOrEmpty() ->
                            throw IllegalArgumentException(
                                "Key binding conflict: both 'jwk' and 'kid' are set, only one must be provided as per OID4VCI spec."
                            )

                        else -> // same as jsonWebKey == null && keyId.isNullOrEmpty()
                            throw IllegalArgumentException(
                                "Key binding missing: neither 'jwk' nor 'kid' is set, exactly one must be provided as per OID4VCI spec."
                            )
                    }

                }.invoke(
                    OpenIdConstants.PROOF_JWT_TYPE,
                    JsonWebToken(
                        issuer = clientId, // omit when token was pre-authn?
                        audience = credentialIssuer,
                        issuedAt = clock.now().truncateToSeconds(),
                        nonce = clientNonce,
                    ),
                    JsonWebToken.serializer(),
                ).getOrThrow().jws
            )
        )
    }

    internal suspend fun createCredentialRequestProofAttestation(
        clientNonce: String?,
        credentialIssuer: String?,
        keyAttestationRequired: KeyAttestationRequired? = null,
        supportedAlgorithms: Collection<String>? = null,
    ): CredentialRequestProofContainer = CredentialRequestProofContainer(
        attestation = setOf(
            (loadKeyAttestation?.invoke(
                KeyAttestationInput(
                    credentialIssuer = credentialIssuer,
                    clientNonce = clientNonce,
                    supportedAlgorithms = supportedAlgorithms,
                    preferredKeyStorageStatusPeriod = keyAttestationRequired?.preferredTtl,
                )
            )?.getOrThrow()?.jws ?: throw IllegalArgumentException("Key attestation required, none provided"))
        )
    )

    private fun JwsCompactTyped<KeyAttestationJwt>.requireKeyMaterialAtAttestedKeyIndex0() {
        val attestedKey = payload.attestedKeys.firstOrNull()
            ?: throw IllegalArgumentException("Key attestation required, none provided")
        if (attestedKey.jwkThumbprintPlain != keyMaterial.jsonWebKey.jwkThumbprintPlain) {
            throw IllegalArgumentException("Key attestation attested_keys[0] must match credential proof signing key")
        }
    }

    private val JsonWebKey.jwkThumbprintPlain: String
        get() = jwkThumbprint.removePrefix("urn:ietf:params:oauth:jwk-thumbprint:sha256:")

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
                issuerSigned = coseCompliantSerializer.decodeFromByteArray<IssuerSigned>(decodeToByteArray(Base64())),
                scheme = credentialScheme as IsoMdocCredentialScheme
            )
        }.getOrElse { throw Exception("Invalid credential format: $this", it) }
    }
}
