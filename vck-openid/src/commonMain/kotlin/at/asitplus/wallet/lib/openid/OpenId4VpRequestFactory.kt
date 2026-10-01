package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OAuth2AuthorizationServerMetadata
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.openid.SupportedAlgorithmsContainerIso
import at.asitplus.openid.SupportedAlgorithmsContainerJwt
import at.asitplus.openid.SupportedAlgorithmsContainerSdJwt
import at.asitplus.openid.VpFormatsSupported
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.cosef.toCoseAlgorithm
import at.asitplus.signum.indispensable.josef.JsonWebKey
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JweAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.JweHeader
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.toEncryptionJsonWebKey
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
import at.asitplus.wallet.lib.extensions.getEncryptionTargetKey
import at.asitplus.wallet.lib.jws.EncryptJwe
import at.asitplus.wallet.lib.jws.EncryptJweFun
import at.asitplus.wallet.lib.jws.JwsContentTypeConstants
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.utils.MapStore
import kotlin.coroutines.cancellation.CancellationException

/** How to populate `iss`/`aud` when signing an OpenID4VP request object. */
internal sealed interface RequestObjectSigning {
    /** OpenID4VP over redirect (URL/QR): `aud` is the OID4VP §5.8 symbolic value, `iss` likewise. */
    data object Redirect : RequestObjectSigning

    /** OpenID4VP over the DC API: `iss` is the client identifier (RFC 9101), no `aud`. */
    data object DcApi : RequestObjectSigning
}

/**
 * Builds and stores OpenID4VP authentication requests, independently of the transport that will carry them:
 * URL/QR (see [OpenId4VpVerifier]) or the W3C Digital Credentials API (see [DcApiVerifier]).
 *
 * The request content is derived entirely from [OpenId4VpRequestOptions]; the transport only decides how the
 * resulting [AuthenticationRequestParameters] is delivered and, for signed requests, how `iss`/`aud` are set
 * (see [RequestObjectSigning]).
 */
internal class OpenId4VpRequestFactory(
    /** Scheme to use for our client identifier. */
    private val clientIdScheme: ClientIdScheme,
    /** Creates one ephemeral encryption key per authentication request, see OpenID4VP 1.0, Section 8.3. */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService,
    /** Advertised in [metadata] so that holders can encrypt responses, for out-of-band metadata only. */
    private val decryptionKeyMaterial: KeyMaterial?,
    /** Signs authentication requests in [createSignedRequestObject]. */
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters>,
    /** Creates OpenID4VP request nonces. */
    private val nonceService: NonceService,
    /** Advertised in [metadata]. */
    supportedAlgorithms: Set<SignatureAlgorithm>,
    /** Used to store issued authn requests to verify the authn response to it. */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters>,
    /** Algorithms supported to decrypt responses from wallets and to encrypt request objects. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption>,
    /** Encrypts the request object, if the wallet asked us to in its `wallet_metadata`, see [createRequestObject]. */
    private val encryptRequestObject: EncryptJweFun = EncryptJwe(),
) {

    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }
    private val supportedJweEncryptionAlgorithmStrings = supportedJweEncryptionAlgorithms
        .map { it.identifier }.toSet()

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption, i.e. without any key to encrypt
     * responses to: those are advertised by [metadataWithEncryption] resp. [metadataWithEphemeralEncryptionKey].
     */
    val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = listOfNotNull((clientIdScheme as? ClientIdScheme.RedirectUri)?.redirectUri),
            vpFormatsSupported = VpFormatsSupported(
                vcJwt = SupportedAlgorithmsContainerJwt(
                    algorithmStrings = supportedJwsAlgorithms.toSet()
                ),
                dcSdJwt = SupportedAlgorithmsContainerSdJwt(
                    sdJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
                    kbJwtAlgorithmStrings = supportedJwsAlgorithms.toSet(),
                ),
                msoMdoc = SupportedAlgorithmsContainerIso(
                    issuerAuthAlgorithmInts = supportedCoseAlgorithms.toSet(),
                    deviceAuthAlgorithmInts = supportedCoseAlgorithms.toSet(),
                ),
            )
        )
    }

    /**
     * Creates the [RelyingPartyMetadata], but with parameters set to request encryption of pushed authentication
     * responses, see [RelyingPartyMetadata.encryptedResponseEncValues].
     *
     * Carries the long-lived [decryptionKeyMaterial], so this is only useful to publish out-of-band, for client
     * identifier schemes that do not convey client metadata in the request itself. Requests built here embed a key
     * specific to that request instead, see [metadataWithEphemeralEncryptionKey].
     */
    val metadataWithEncryption by lazy {
        metadataRequestingEncryptedResponses(decryptionKeyMaterial?.toEncryptionJsonWebKey())
    }

    /**
     * Creates the [RelyingPartyMetadata] with an encryption key valid for exactly one authentication request, as
     * required by
     * [OpenID4VP 1.0, 8.3](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-encrypted-responses)
     * and
     * [OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html),
     */
    private suspend fun metadataWithEphemeralEncryptionKey(): RelyingPartyMetadata =
        metadataRequestingEncryptedResponses(ephemeralEncryptionKeyService.createKey().toEncryptionJsonWebKey())

    /** [encryptionKey] is the only key advertised, so that holders can't pick anything else to encrypt to. */
    private fun metadataRequestingEncryptedResponses(encryptionKey: JsonWebKey?): RelyingPartyMetadata = metadata.copy(
        encryptedResponseEncValuesSupportedString = supportedJweEncryptionAlgorithmStrings,
        jsonWebKeySet = encryptionKey?.let { JsonWebKeySet(listOf(it)) },
    )

    suspend fun createPlainAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        requestObjectParameters: RequestObjectParameters? = null,
    ): AuthenticationRequestParameters = requestOptions.toAuthnRequest(requestObjectParameters)
        .also { storeAuthnRequest(it, requestOptions.state) }

    suspend fun createSignedRequestObject(
        requestOptions: OpenId4VpRequestOptions,
        signing: RequestObjectSigning,
        requestObjectParameters: RequestObjectParameters? = null,
    ): KmmResult<JwsCompactTyped<AuthenticationRequestParameters>> = catching {
        val requestObject = createPlainAuthnRequest(requestOptions, requestObjectParameters)
        val preRegisteredIssuer = (clientIdScheme as? ClientIdScheme.PreRegistered)
            ?.let { it.issuerUri ?: it.clientId }
        val signedRequestObject = when (signing) {
            RequestObjectSigning.Redirect -> requestObject.copy(
                audience = SELF_ISSUED_AUDIENCE,
                issuer = preRegisteredIssuer ?: SELF_ISSUED_AUDIENCE,
            )

            RequestObjectSigning.DcApi -> requestObject.copy(
                // per RFC 9101, `iss` is the client identifier; wallets identify us via
                // client_id and the request signature, an audience cannot be known upfront
                issuer = preRegisteredIssuer ?: clientIdScheme.clientId,
            )
        }
        signAuthnRequest(
            JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST,
            signedRequestObject,
            AuthenticationRequestParameters.serializer(),
        ).getOrThrow()
    }

    /**
     * Creates the request object to serve at the `request_uri` endpoint: a signed request object, encrypted to the
     * wallet's key if it passed one in its `wallet_metadata`, as per
     * [OpenID4VP 1.0, 5.10](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-request-uri-method-post).
     */
    suspend fun createRequestObject(
        requestOptions: OpenId4VpRequestOptions,
        signing: RequestObjectSigning,
        requestObjectParameters: RequestObjectParameters? = null,
    ): KmmResult<String> = catching {
        val signed = createSignedRequestObject(requestOptions, signing, requestObjectParameters).getOrThrow().toString()
        val encryptionTarget = requestObjectParameters?.walletMetadata?.encryptionTarget
        if (encryptionTarget == null) {
            signed
        } else {
            encryptRequestObject(
                header = JweHeader(
                    algorithm = JweAlgorithm.ECDH_ES,
                    encryption = encryptionTarget.second,
                    keyId = encryptionTarget.first.keyId,
                    // RFC 7519, 5.2: a nested JWT, i.e. our signed request object inside this JWE, MUST declare `JWT`
                    contentType = "JWT",
                ),
                payload = signed,
                recipientKey = encryptionTarget.first,
            ).getOrThrow().serialize()
        }
    }

    /**
     * The wallet's encryption key and the content encryption algorithm to use, or `null` if the wallet did not ask for
     * an encrypted request object, or asked for algorithms we don't support.
     */
    private val OAuth2AuthorizationServerMetadata.encryptionTarget: Pair<JsonWebKey, JweEncryption>?
        get() {
            val recipientKey = jsonWebKeySet?.keys?.getEncryptionTargetKey()
                ?: return null
            requestObjectEncryptionAlgValuesSupported?.let {
                if (JweAlgorithm.ECDH_ES !in it)
                    return null
            }
            // the wallet expressing no preference means the OpenID4VP default, otherwise we need a common algorithm
            val jweEncryption = requestObjectEncryptionEncValuesSupported
                ?.let { advertised -> advertised.firstOrNull { it in supportedJweEncryptionAlgorithms } ?: return null }
                ?: JweEncryption.A128GCM
            return recipientKey to jweEncryption
        }

    suspend fun storeAuthnRequest(
        authenticationRequestParameters: AuthenticationRequestParameters,
        externalId: String? = null,
    ) = stateToAuthnRequestStore.put(
        key = externalId
            ?: authenticationRequestParameters.state
            ?: throw IllegalArgumentException("Neither externalId nor state has been provided"),
        value = authenticationRequestParameters,
    )

    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun loadAuthnRequest(
        input: ResponseParametersFrom,
        externalId: String? = null,
    ): AuthenticationRequestParameters {
        val storedId = externalId
            ?: input.parameters.state
            ?: throw IllegalArgumentException("Neither externalId nor state given")
        val authnRequest = stateToAuthnRequestStore.remove(storedId)
            ?: throw IllegalArgumentException("No authn request found for $storedId")
        val ephemeralKey = authnRequest.clientMetadata?.jsonWebKeySet?.keys?.getEncryptionTargetKey()
        val ephemeralKeyId = ephemeralKey?.keyId
        if (authnRequest.responseMode?.requiresEncryption == true) {
            require(input is ResponseParametersFrom.JweDecrypted) {
                "response_mode requires encryption, but no encrypted response was given"
            }
            val responseKeyId = input.jweDecrypted.header.keyId
            if (ephemeralKey != null) {
                requireNotNull(ephemeralKeyId) { "Authentication request encryption key has no kid" }
                require(responseKeyId == ephemeralKeyId) {
                    "Encrypted response key does not match the authentication request"
                }
            } else {
                requireNotNull(decryptionKeyMaterial) { "No decryption key configured" }
                require(responseKeyId == null || responseKeyId == decryptionKeyMaterial.identifier) {
                    "Encrypted response key does not match the configured decryption key"
                }
            }
        }
        return authnRequest
    }

    private suspend fun OpenId4VpRequestOptions.toAuthnRequest(
        requestObjectParameters: RequestObjectParameters?,
    ): AuthenticationRequestParameters {
        // one ephemeral encryption key per request, so this must be evaluated exactly once
        val clientMetadata = clientMetadata()
        if (isAnyDcApi && responseMode.requiresEncryption) {
            // The DC API has no other channel to convey the verifier's encryption key: wallets can only encrypt
            // responses with a key from the client metadata in the request itself.
            requireNotNull(clientMetadata?.jsonWebKeySet) {
                "Encrypted responses require client metadata with a JSON Web Key Set in the request, " +
                        "which is not populated for this client identifier scheme"
            }
        }
        return AuthenticationRequestParameters(
            responseType = responseType,
            clientId = if (populateClientId) clientIdScheme.clientId else null,
            redirectUrl = if (!isAnyDirectPost) clientIdScheme.redirectUri else null,
            responseUrl = responseUrl,
            // Using scope as an alias for a well-defined DCQL Query is not supported
            scope = null,
            nonce = nonceService.provideNonce(),
            walletNonce = requestObjectParameters?.walletNonce,
            clientMetadata = clientMetadata,
            responseMode = responseMode,
            // the DC API binds request and response through the browser, not through a `state`
            state = if (isAnyDcApi) null else state,
            dcqlQuery = (presentationRequest as? DCQLRequest)?.dcqlQuery,
            transactionData = transactionData?.map { it.toBase64UrlJsonString() },
            expectedOrigins = expectedOrigins,
            verifierInfo = verifierInfo,
        )
    }

    private suspend fun OpenId4VpRequestOptions.clientMetadata(): RelyingPartyMetadata? = when (verifierMetadataMode) {
        VerifierMetadataMode.OMIT_IF_OUT_OF_BAND -> null
        VerifierMetadataMode.AUTO -> when (clientIdScheme) {
            is ClientIdScheme.RedirectUri,
            is ClientIdScheme.VerifierAttestation,
            is ClientIdScheme.CertificateSanDns,
            is ClientIdScheme.CertificateHash,
                -> if (responseMode.requiresEncryption) metadataWithEphemeralEncryptionKey() else metadata

            else -> null
        }
    }

    companion object {
        /**
         * [OpenID4VP 5.8](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-aud-of-a-request-object)
         * `https://self-issued.me/v2` is a symbolic string and can be used as an `aud` claim value even when this
         * specification is used standalone, without SIOPv2.
         */
        private const val SELF_ISSUED_AUDIENCE = "https://self-issued.me/v2"
    }
}
