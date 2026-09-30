package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.JarRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.RequestObjectParameters
import at.asitplus.openid.ResponseParametersFrom
import at.asitplus.rfc6749OAuth2AuthorizationFramework.ResponseType
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.josef.JweEncryption
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.wallet.lib.DefaultNonceService
import at.asitplus.wallet.lib.MdocDeviceSignatureVerifier
import at.asitplus.wallet.lib.NonceService
import at.asitplus.wallet.lib.agent.EphemeralEncryptionKeyService
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier
import at.asitplus.wallet.lib.agent.NonceChallengeVerifier.ChallengeSession
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.agent.VerifierAgent
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.jws.DecryptJweFun
import at.asitplus.wallet.lib.jws.DecryptJweWithEphemeralKey
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.openid.encodeToParameters
import at.asitplus.wallet.lib.openid.ClientIdScheme.CertificateHash
import at.asitplus.wallet.lib.openid.ClientIdScheme.CertificateSanDns
import at.asitplus.wallet.lib.openid.ClientIdScheme.RedirectUri
import at.asitplus.wallet.lib.utils.DefaultMapStore
import at.asitplus.wallet.lib.utils.MapStore
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads
import kotlin.time.Clock

/**
 * Combines Verifiable Presentations with OAuth 2.0.
 * Implements [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) (1.0, 2025-07-09).
 *
 * This class creates the Authentication Request (see [AuthenticationRequestParameters]),
 * clients need to send it to the holder (see [OpenId4VpHolder]) which will create the Authentication Response,
 * which will be verified here in [validateAuthnResponse].
 */
class OpenId4VpVerifier @JvmOverloads constructor(
    /** Scheme to use for our client identifier. */
    private val clientIdScheme: ClientIdScheme,
    /** Key material to sign the authentication request with [signAuthnRequest]. */
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    /** Verifies the holder's response against our identifier from [clientIdScheme]. */
    val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    /**
     * Long-lived key advertised in [metadata] so that holders can encrypt responses, but **only** for client
     * identifier schemes that do not convey client metadata in the request, i.e. where this key is distributed
     * out-of-band. This is not conformant to OpenID4VC HAIP, so leave it `null` to have every request carry its own
     * ephemeral encryption key, see [ephemeralEncryptionKeyService].
     */
    private val decryptionKeyMaterial: KeyMaterial? = null,
    /** Creates one ephemeral encryption key per authentication request, see OpenID4VP 1.0, Section 8.3. */
    private val ephemeralEncryptionKeyService: EphemeralEncryptionKeyService = EphemeralEncryptionKeyService(),
    @Deprecated("Will be derived from [ephemeralEncryptionKeyService] and [decryptionKeyMaterial]")
    private val decryptJwe: DecryptJweFun =
        DecryptJweWithEphemeralKey(ephemeralEncryptionKeyService, decryptionKeyMaterial),
    /** Signs authentication requests in [OpenId4VpRequestFactory]. */
    private val signAuthnRequest: SignJwtFun<AuthenticationRequestParameters> =
        SignJwt(keyMaterial, JwsHeaderClientIdScheme(clientIdScheme)),
    /** Validates signed responses from holders. */
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    /** Advertised in [metadata]. */
    private val supportedAlgorithms: Set<SignatureAlgorithm> = setOf(SignatureAlgorithm.ECDSAwithSHA256),
    /** Used to verify session transcripts from mDoc responses. */
    private val verifyCoseSignature: VerifyCoseSignatureWithKeyFun<ByteArray> = VerifyCoseSignatureWithKey(),
    @Deprecated("Support for SIOPv2 has been removed")
    private val timeLeewaySeconds: Long = 300L,
    @Deprecated("Support for SIOPv2 has been removed")
    private val clock: Clock = Clock.System,
    /** Creates and validates OpenID4VP request nonces. */
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
    /** Algorithms supported to decrypt responses from wallets, for [metadataWithEncryption]. */
    private val supportedJweEncryptionAlgorithms: Set<JweEncryption> = JweEncryption.entries.toSet(),
) {
    private val nonceAwareVerifier = NonceChallengeVerifier(
        verifierId = clientIdScheme.clientId,
        verifier = verifier,
        nonceService = nonceService,
    )
    private val requestFactory = OpenId4VpRequestFactory(
        clientIdScheme = clientIdScheme,
        ephemeralEncryptionKeyService = ephemeralEncryptionKeyService,
        decryptionKeyMaterial = decryptionKeyMaterial,
        signAuthnRequest = signAuthnRequest,
        nonceService = nonceService,
        supportedAlgorithms = supportedAlgorithms,
        stateToAuthnRequestStore = stateToAuthnRequestStore,
        supportedJweEncryptionAlgorithms = supportedJweEncryptionAlgorithms,
    )
    private val vpTokenValidator = VpTokenValidator(
        mdocDeviceSignatureVerifier = MdocDeviceSignatureVerifier(verifyCoseSignature = verifyCoseSignature),
        createSessionTranscript = UrlSessionTranscriptCalculator(),
        decryptionKeyMaterial = decryptionKeyMaterial
    )

    private val responseParser = ResponseParser(
        decryptJwe = DecryptJweWithEphemeralKey(ephemeralEncryptionKeyService, decryptionKeyMaterial),
        verifyJwsObject = verifyJwsObject
    )

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption, i.e. without any key to encrypt
     * responses to (see [metadataWithEncryption])
     */
    val metadata get() = requestFactory.metadata

    /**
     * Creates the [RelyingPartyMetadata], but with parameters set to request encryption of pushed authentication
     * responses, see [RelyingPartyMetadata.encryptedResponseEncValues], advertising [decryptionKeyMaterial].
     *
     * Only useful to publish out-of-band: requests carry a key specific to that request instead.
     */
    val metadataWithEncryption get() = requestFactory.metadataWithEncryption

    /**
     * Creates a new authentication request conforming to OpenID4VP.
     */
    @Suppress("DEPRECATION_ERROR")
    suspend fun createAuthnRequest(
        requestOptions: OpenId4VpRequestOptions,
        creationOptions: CreationOptions,
    ): KmmResult<CreatedRequest> = catching {
        when (creationOptions) {
            is CreationOptions.Query -> {
                require(clientIdScheme !is CertificateHash && clientIdScheme !is CertificateSanDns) {
                    "Requests using x509_hash or x509_san_dns client schemes must be signed"
                }
                URLBuilder(creationOptions.walletUrl).apply {
                    requestFactory.createPlainAuthnRequest(requestOptions).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest()
            }

            is CreationOptions.RequestByReference -> {
                require(clientIdScheme !is CertificateHash && clientIdScheme !is CertificateSanDns) {
                    "Requests using x509_hash or x509_san_dns client schemes must be signed"
                }
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        requestUri = creationOptions.requestUrl,
                        requestUriMethod = creationOptions.requestUrlMethod,
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest {
                    catching {
                        joseCompliantSerializer.encodeToString(
                            requestFactory.createPlainAuthnRequest(requestOptions, it)
                        )
                    }
                }
            }

            is CreationOptions.SignedRequestByValue -> {
                require(clientIdScheme !is RedirectUri) {
                    "Requests using redirect_uri client scheme can't be signed per OpenID4VP 1.0 5.9.3."
                }
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        request = requestFactory.createSignedRequestObject(
                            requestOptions,
                            RequestObjectSigning.Redirect
                        ).getOrThrow().toString(),
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString().toCreatedRequest()
            }

            is CreationOptions.SignedRequestByReference -> {
                require(clientIdScheme !is RedirectUri) {
                    "Requests using redirect_uri client scheme can't be signed per OpenID4VP 1.0 5.9.3."
                }
                URLBuilder(creationOptions.walletUrl).apply {
                    JarRequestParameters(
                        clientId = clientIdScheme.clientId,
                        requestUri = creationOptions.requestUrl,
                        requestUriMethod = creationOptions.requestUrlMethod,
                    ).encodeToParameters()
                        .forEach { parameters.append(it.key, it.value) }
                }.buildString()
                    .toCreatedRequest {
                        requestFactory.createRequestObject(requestOptions, RequestObjectSigning.Redirect, it)
                    }
            }
        }
    }

    private fun String.toCreatedRequest() = CreatedRequest(this)
    private fun String.toCreatedRequest(
        loadRequestObject: suspend (RequestObjectParameters?) -> KmmResult<String>,
    ) = CreatedRequest(this, loadRequestObject)

    /**
     * Validates an Authentication Response from the Wallet, where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     */
    suspend fun validateAuthnResponse(
        input: String,
    ): KmmResult<AuthnResponseResult> = catching {
        val response = responseParser.parseAuthnResponse(input)
        validateAuthnResponse(response).getOrThrow()
    }

    /**
     * Validates an Authentication Response from the Wallet,
     * in case it has been parsed into [ResponseParametersFrom] with [ResponseParser].
     */
    suspend fun validateAuthnResponse(
        input: ResponseParametersFrom,
    ) = catching {
        Napier.d("validateAuthnResponse: $input")
        val authnRequest = requestFactory.loadAuthnRequest(input)

        // the request has been consumed above, and an authentication response is not retryable,
        // so end the challenge's lifecycle here, no matter how validating the response turns out
        val session = nonceAwareVerifier.consumeChallenge(
            authnRequest.nonce ?: throw IllegalArgumentException("nonce not present in $authnRequest")
        )

        val responseType = authnRequest.responseType?.let { ResponseType(it) }
        require(responseType != null) {
            "No response type was specified in the original authentication request."
        }
        require(OpenIdConstants.VP_TOKEN in responseType) {
            "Response type must contain `vp_token`"
        }

        AuthnResponseResult(
            idTokenValidationResult = null,
            vpTokenValidationResult = validateVpToken(authnRequest, input, session),
            request = authnRequest,
        )
    }

    /**
     * Validates the `vp_token` of the response with the shared [VpTokenValidator],
     * enforcing this verifier's transport: URL/QR, i.e. anything but the Digital Credentials API.
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun validateVpToken(
        authnRequest: AuthenticationRequestParameters,
        responseParameters: ResponseParametersFrom,
        session: ChallengeSession,
    ): KmmResult<VpTokenValidationResult> = catching {
        require(responseParameters.originalResponseParameters !is ResponseParametersFrom.DcApi) {
            "DCAPI verification is not supported, use DcApiVerifier"
        }
        vpTokenValidator.validateVpToken(
            authnRequest = authnRequest,
            responseParameters = responseParameters,
            origin = null,
            session = session,
        ).getOrThrow()
    }
}


