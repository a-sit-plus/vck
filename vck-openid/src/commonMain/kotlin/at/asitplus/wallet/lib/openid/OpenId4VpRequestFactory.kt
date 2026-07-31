package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
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
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.signum.indispensable.josef.toJwsAlgorithm
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.DCQLRequest
import at.asitplus.wallet.lib.data.toBase64UrlJsonString
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
    /** Advertised in [metadata] so that holders can encrypt responses. */
    private val decryptionKeyMaterial: KeyMaterial,
    /** Signs authentication requests in [createSignedRequestObject]. */
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters>,
    /** Creates OpenID4VP request nonces. */
    private val nonceService: NonceService,
    /** Advertised in [metadata]. */
    supportedAlgorithms: Set<SignatureAlgorithm>,
    /** Used to store issued authn requests to verify the authn response to it. */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters>,
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption>,
) {

    private val supportedJwsAlgorithms = supportedAlgorithms
        .mapNotNull { it.toJwsAlgorithm().getOrNull()?.identifier }
    private val supportedCoseAlgorithms = supportedAlgorithms
        .mapNotNull { it.toCoseAlgorithm().getOrNull()?.coseValue }

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption (see [metadataWithEncryption])
     */
    val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = listOfNotNull((clientIdScheme as? ClientIdScheme.RedirectUri)?.redirectUri),
            jsonWebKeySet = JsonWebKeySet(
                listOf(
                    decryptionKeyMaterial.publicKey.toJsonWebKey(decryptionKeyMaterial.identifier).withAlgorithm()
                )
            ),
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
     */
    val metadataWithEncryption by lazy {
        metadata.copy(
            encryptedResponseEncValuesSupportedString = supportedJweEncryptionAlgorithms.map { it.identifier }.toSet(),
            jsonWebKeySet = metadata.jsonWebKeySet?.let {
                JsonWebKeySet(it.keys.map { it.copy(publicKeyUse = "enc") })
            }
        )
    }

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
        val authnRequest = stateToAuthnRequestStore.get(storedId)
            ?: throw IllegalArgumentException("No authn request found for $storedId")
        if (authnRequest.responseMode?.requiresEncryption == true)
            require(input.hasBeenEncrypted) {
                "response_mode requires encryption, but no encrypted response was given"
            }
        return authnRequest
    }

    /**
     * The DC API has no other channel to convey the verifier's encryption key: wallets can only encrypt responses
     * with a key from [at.asitplus.openid.AuthenticationRequestParameters.clientMetadata] in the request itself.
     */
    fun requireEncryptionKeyConveyed(requestOptions: OpenId4VpRequestOptions): OpenId4VpRequestOptions =
        requestOptions.also {
            if (it.responseMode.requiresEncryption) {
                requireNotNull(it.clientMetadata()?.jsonWebKeySet) {
                    "Encrypted responses require client metadata with a JSON Web Key Set in the request, " +
                            "which is not populated for this client identifier scheme"
                }
            }
        }

    private suspend fun OpenId4VpRequestOptions.toAuthnRequest(
        requestObjectParameters: RequestObjectParameters?,
    ): AuthenticationRequestParameters = AuthenticationRequestParameters(
        responseType = responseType,
        clientId = if (populateClientId) clientIdScheme.clientId else null,
        redirectUrl = if (!isAnyDirectPost) clientIdScheme.redirectUri else null,
        responseUrl = responseUrl,
        // Using scope as an alias for a well-defined DCQL Query is not supported
        scope = null,
        nonce = nonceService.provideNonce(),
        walletNonce = requestObjectParameters?.walletNonce,
        clientMetadata = clientMetadata(),
        responseMode = responseMode,
        // the DC API binds request and response through the browser, not through a `state`
        state = if (isAnyDcApi) null else state,
        dcqlQuery = (presentationRequest as? DCQLRequest)?.dcqlQuery,
        transactionData = transactionData?.map { it.toBase64UrlJsonString() },
        expectedOrigins = expectedOrigins,
        verifierInfo = verifierInfo,
    )

    private fun OpenId4VpRequestOptions.clientMetadata(): RelyingPartyMetadata? = when (verifierMetadataMode) {
        VerifierMetadataMode.OMIT_IF_OUT_OF_BAND -> null
        VerifierMetadataMode.AUTO -> when (clientIdScheme) {
            is ClientIdScheme.RedirectUri,
            is ClientIdScheme.VerifierAttestation,
            is ClientIdScheme.CertificateSanDns,
            is ClientIdScheme.CertificateHash,
                -> if (responseMode.requiresEncryption) metadataWithEncryption else metadata

            else -> null
        }
    }

    // should always be ecdh-es for encryption
    private fun JsonWebKey.withAlgorithm(): JsonWebKey = this.copy(algorithm = JweAlgorithm.ECDH_ES)

    companion object {
        /**
         * [OpenID4VP 5.8](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-aud-of-a-request-object)
         * `https://self-issued.me/v2` is a symbolic string and can be used as an `aud` claim value even when this
         * specification is used standalone, without SIOPv2.
         */
        private const val SELF_ISSUED_AUDIENCE = "https://self-issued.me/v2"
    }
}
