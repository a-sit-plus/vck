package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.*
import at.asitplus.jsonpath.JsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.openid.*
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.JsonWebKeySet
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.*
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.ConstantIndex.supportsSdJwt
import at.asitplus.wallet.lib.data.ConstantIndex.supportsVcJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.*
import at.asitplus.wallet.lib.oidvci.*
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonPrimitive
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.DurationUnit
import kotlin.time.toDuration

/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * This class creates the Authentication Request, [verifier] verifies the response. See [at.asitplus.wallet.lib.oidc.OidcSiopWallet] for the holder.
 */
class OpenId4VpVerifier(
    private val clientIdScheme: ClientIdScheme,
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val verifier: Verifier = VerifierAgent(identifier = clientIdScheme.clientId),
    private val jwsService: JwsService = DefaultJwsService(DefaultCryptoService(keyMaterial)),
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(DefaultVerifierCryptoService()),
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
    private val nonceService: NonceService = DefaultNonceService(),
    /** Used to store issued authn requests, to verify the authn response to it */
    private val stateToAuthnRequestStore: MapStore<String, AuthenticationRequestParameters> = DefaultMapStore(),
) {

    private val responseParser = ResponseParser(jwsService, verifierJwsService)
    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val containerJwt =
        FormatContainerJwt(algorithmStrings = verifierJwsService.supportedAlgorithms.map { it.identifier })

    /**
     * Serve this result JSON-serialized under `/.well-known/jar-issuer`
     * (see [OpenIdConstants.PATH_WELL_KNOWN_JAR_ISSUER]),
     * so that SIOP Wallets can look up the keys used to sign request objects.
     */
    val jarMetadata: JwtVcIssuerMetadata by lazy {
        JwtVcIssuerMetadata(
            issuer = clientIdScheme.clientId,
            jsonWebKeySet = JsonWebKeySet(setOf(jwsService.keyMaterial.jsonWebKey))
        )
    }

    /**
     * Creates the [at.asitplus.openid.RelyingPartyMetadata], without encryption (see [metadataWithEncryption])
     */
    val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = listOfNotNull((clientIdScheme as? ClientIdScheme.RedirectUri)?.clientId),
            jsonWebKeySet = JsonWebKeySet(listOf(keyMaterial.publicKey.toJsonWebKey())),
            subjectSyntaxTypesSupported = setOf(
                OpenIdConstants.URN_TYPE_JWK_THUMBPRINT,
                OpenIdConstants.PREFIX_DID_KEY,
                OpenIdConstants.BINDING_METHOD_JWK
            ),
            vpFormats = FormatHolder(
                msoMdoc = containerJwt,
                jwtVp = containerJwt,
                jwtSd = containerJwt,
            )
        )
    }

    /**
     * Creates the [RelyingPartyMetadata], but with parameters set to request encryption of pushed authentication
     * responses, see [RelyingPartyMetadata.authorizationEncryptedResponseAlg]
     * and [RelyingPartyMetadata.authorizationEncryptedResponseEncoding].
     */
    val metadataWithEncryption by lazy {
        metadata.copy(
            authorizationEncryptedResponseAlgString = jwsService.encryptionAlgorithm.identifier,
            authorizationEncryptedResponseEncodingString = jwsService.encryptionEncoding.text
        )
    }

    /**
     * Create a URL to be displayed as a static QR code for Wallet initiation.
     * URL is the [walletUrl], with query parameters appended for [clientMetadataUrl], [requestUrl] and
     * [clientIdScheme.clientId].
     */
    fun createQrCodeUrl(
        walletUrl: String,
        clientMetadataUrl: String,
        requestUrl: String,
    ): String {
        val urlBuilder = URLBuilder(walletUrl)
        AuthenticationRequestParameters(
            clientId = clientIdScheme.clientId,
            clientMetadataUri = clientMetadataUrl,
            requestUri = requestUrl,
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return urlBuilder.buildString()
    }

    /**
     * Creates a JWS containing signed [RelyingPartyMetadata],
     * to be served under a `client_metadata_uri` at the Verifier.
     */
    suspend fun createSignedMetadata(): KmmResult<JwsSigned<RelyingPartyMetadata>> =
        jwsService.createSignedJwsAddingParams(
            payload = metadata,
            serializer = RelyingPartyMetadata.Companion.serializer(),
            addKeyId = true,
            addX5c = false
        )

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl].
     */
    suspend fun createAuthnRequestUrl(
        walletUrl: String,
        requestOptions: RequestOptions,
    ): String {
        val urlBuilder = URLBuilder(walletUrl)
        createAuthnRequest(requestOptions).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return urlBuilder.buildString()
    }

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl],
     * containing a JWS Authorization Request (JAR, RFC9101) in `request`, containing the request parameters itself.
     */
    suspend fun createAuthnRequestUrlWithRequestObject(
        walletUrl: String,
        requestOptions: RequestOptions,
    ): KmmResult<String> = catching {
        val jar = createAuthnRequestAsSignedRequestObject(requestOptions).getOrThrow()
        val urlBuilder = URLBuilder(walletUrl)
        AuthenticationRequestParameters(
            clientId = clientIdScheme.clientId,
            request = jar.serialize(),
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        urlBuilder.buildString()
    }

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl],
     * containing a reference (`request_uri`, see [AuthenticationRequestParameters.requestUri]) to the
     * JWS Authorization Request (JAR, RFC9101), containing the request parameters itself.
     *
     * @param requestUrl the URL where the request itself can be loaded by the client
     * @return The URL to display to the Wallet, and the JWS that shall be made accessible under [requestUrl]
     */
    suspend fun createAuthnRequestUrlWithRequestObjectByReference(
        walletUrl: String,
        requestUrl: String,
        requestOptions: RequestOptions,
    ): KmmResult<Pair<String, String>> = catching {
        val jar = createAuthnRequestAsSignedRequestObject(requestOptions).getOrThrow()
        val urlBuilder = URLBuilder(walletUrl)
        AuthenticationRequestParameters(
            clientId = clientIdScheme.clientId,
            requestUri = requestUrl,
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        urlBuilder.buildString() to jar.serialize()
    }

    /**
     * Creates an JWS Authorization Request (JAR, RFC9101), wrapping the usual [AuthenticationRequestParameters].
     *
     * To use this for an Authentication Request with `request_uri`, use the following code,
     * `jar` being the result of this function:
     * ```
     * val urlToSendToWallet = io.ktor.http.URLBuilder(walletUrl).apply {
     *    parameters.append("client_id", clientId)
     *    parameters.append("request_uri", requestUrl)
     * }.buildString()
     * // on an GET to requestUrl, return `jar.serialize()`
     * ```
     */
    suspend fun createAuthnRequestAsSignedRequestObject(
        requestOptions: RequestOptions,
    ): KmmResult<JwsSigned<AuthenticationRequestParameters>> = catching {
        val requestObject = createAuthnRequest(requestOptions)
        val attestationJwt = (clientIdScheme as? ClientIdScheme.VerifierAttestation)?.attestationJwt?.serialize()
        val certificateChain = (clientIdScheme as? ClientIdScheme.CertificateSanDns)?.chain
        val issuer = (clientIdScheme as? ClientIdScheme.PreRegistered)?.clientId ?: "https://self-issued.me/v2"
        jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = jwsService.algorithm,
                attestationJwt = attestationJwt,
                certificateChain = certificateChain,
                type = JwsContentTypeConstants.OAUTH_AUTHZ_REQUEST
            ),
            payload = requestObject.copy(audience = "https://self-issued.me/v2", issuer = issuer),
            serializer = AuthenticationRequestParameters.Companion.serializer(),
            addJsonWebKey = certificateChain == null,
        ).getOrThrow()
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded as query params appended to the URL of the Wallet,
     * e.g. `https://example.com?repsonse_type=...` (see [createAuthnRequestUrl])
     *
     * Callers may serialize the result with `result.encodeToParameters().formUrlEncode()`
     */
    suspend fun createAuthnRequest(
        requestOptions: RequestOptions,
    ) = AuthenticationRequestParameters(
        responseType = requestOptions.responseType,
        clientId = clientIdScheme.clientId,
        redirectUrl = if (!requestOptions.isAnyDirectPost) clientIdScheme.clientId else null,
        responseUrl = requestOptions.responseUrl,
        clientIdScheme = clientIdScheme.scheme,
        scope = requestOptions.buildScope(),
        nonce = nonceService.provideNonce(),
        clientMetadata = if (requestOptions.clientMetadataUrl != null) {
            null
        } else {
            if (requestOptions.encryption) metadataWithEncryption else metadata
        },
        clientMetadataUri = requestOptions.clientMetadataUrl,
        idTokenType = IdTokenType.SUBJECT_SIGNED.text,
        responseMode = requestOptions.responseMode,
        state = requestOptions.state,
        presentationDefinition = PresentationDefinition(
            id = uuid4().toString(),
            inputDescriptors = requestOptions.credentials.map { it.toInputDescriptor() },
        ),
    ).also { stateToAuthnRequestStore.put(requestOptions.state, it) }

    private fun RequestOptions.buildScope() = (
            listOf(OpenIdConstants.SCOPE_OPENID, OpenIdConstants.SCOPE_PROFILE)
                    + credentials.mapNotNull { it.credentialScheme.sdJwtType }
                    + credentials.mapNotNull { it.credentialScheme.vcType }
                    + credentials.mapNotNull { it.credentialScheme.isoNamespace }
            ).joinToString(" ")

    private val RequestOptions.isAnyDirectPost
        get() = (responseMode == OpenIdConstants.ResponseMode.DirectPost) ||
                (responseMode == OpenIdConstants.ResponseMode.DirectPostJwt)

    //TODO extend for InputDescriptor interface in case QES
    private fun RequestOptionsCredential.toInputDescriptor() = DifInputDescriptor(
        id = buildId(),
        format = toFormatHolder(),
        constraints = toConstraint(),
    )

    /**
     * doctype is not really an attribute that can be presented,
     * encoding it into the descriptor id as in the following non-normative example fow now:
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.3.1-4
     */
    private fun RequestOptionsCredential.buildId() =
        if (credentialScheme.isoDocType != null && representation == ConstantIndex.CredentialRepresentation.ISO_MDOC)
            credentialScheme.isoDocType!! else uuid4().toString()

    private fun RequestOptionsCredential.toConstraint() =
        Constraint(fields = (requiredAttributes() + optionalAttributes() + toTypeConstraint()).filterNotNull())

    private fun RequestOptionsCredential.requiredAttributes() =
        requestedAttributes?.createConstraints(representation, credentialScheme, false)?.toSet()
            ?: setOf()

    private fun RequestOptionsCredential.optionalAttributes() =
        requestedOptionalAttributes?.createConstraints(representation, credentialScheme, true)
            ?: listOf()

    private fun RequestOptionsCredential.toTypeConstraint() = when (representation) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT -> this.credentialScheme.toVcConstraint()
        ConstantIndex.CredentialRepresentation.SD_JWT -> this.credentialScheme.toSdJwtConstraint()
        ConstantIndex.CredentialRepresentation.ISO_MDOC -> null
    }

    private fun RequestOptionsCredential.toFormatHolder() = when (representation) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT -> FormatHolder(jwtVp = containerJwt)
        ConstantIndex.CredentialRepresentation.SD_JWT -> FormatHolder(jwtSd = containerJwt)
        ConstantIndex.CredentialRepresentation.ISO_MDOC -> FormatHolder(msoMdoc = containerJwt)
    }

    private fun ConstantIndex.CredentialScheme.toVcConstraint() = if (supportsVcJwt)
        ConstraintField(
            path = listOf("$.type"),
            filter = ConstraintFilter(
                type = "string",
                pattern = vcType,
            )
        ) else null

    private fun ConstantIndex.CredentialScheme.toSdJwtConstraint() = if (supportsSdJwt)
        ConstraintField(
            path = listOf("$.vct"),
            filter = ConstraintFilter(
                type = "string",
                pattern = sdJwtType!!
            )
        ) else null

    private fun Set<String>.createConstraints(
        representation: ConstantIndex.CredentialRepresentation,
        credentialScheme: ConstantIndex.CredentialScheme?,
        optional: Boolean,
    ): Collection<ConstraintField> = map {
        if (representation == ConstantIndex.CredentialRepresentation.ISO_MDOC)
            credentialScheme.toConstraintField(it, optional)
        else
            ConstraintField(path = listOf("\$[${it.quote()}]"), optional = optional)
    }

    private fun ConstantIndex.CredentialScheme?.toConstraintField(
        attributeType: String,
        optional: Boolean,
    ) = ConstraintField(
        path = listOf(
            NormalizedJsonPath(
                NormalizedJsonPathSegment.NameSegment(this?.isoNamespace ?: "mdoc"),
                NormalizedJsonPathSegment.NameSegment(attributeType),
            ).toString()
        ),
        intentToRetain = false,
        optional = optional,
    )

    /**
     * Validates the OIDC Authentication Response from the Wallet, where [content] are the HTTP POST encoded
     * [at.asitplus.openid.AuthenticationResponseParameters], e.g. `id_token=...&vp_token=...`
     */
    @Deprecated("Use validateAuthnResponse", ReplaceWith("validateAuthnResponse"))
    suspend fun validateAuthnResponseFromPost(content: String): AuthnResponseResult {
        return validateAuthnResponse(content)
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is a map of POST parameters received.
     */
    suspend fun validateAuthnResponse(input: Map<String, String>): AuthnResponseResult {
        val paramsFrom = runCatching {
            ResponseParametersFrom.Post(input.decode<AuthenticationResponseParameters>())
        }.getOrElse {
            Napier.w("Could not parse authentication response: $input", it)
            return AuthnResponseResult.Error("Can't parse input", null)
        }
        return validateAuthnResponse(paramsFrom)
    }

    /**
     * Validates an Authentication Response from the Wallet, where [input] is either:
     * - a URL, containing parameters in the fragment, e.g. `https://example.com#id_token=...`
     * - a URL, containing parameters in the query, e.g. `https://example.com?id_token=...`
     * - parameters encoded as a POST body, e.g. `id_token=...&vp_token=...`
     */
    suspend fun validateAuthnResponse(input: String): AuthnResponseResult {
        val paramsFrom = runCatching {
            responseParser.parseAuthnResponse(input)
        }.getOrElse {
            Napier.w("Could not parse authentication response: $input", it)
            return AuthnResponseResult.Error("Can't parse input", null)
        }
        return validateAuthnResponse(paramsFrom)
    }

    /**
     * Validates [AuthenticationResponseParameters] from the Wallet
     */
    suspend fun validateAuthnResponse(input: ResponseParametersFrom): AuthnResponseResult {
        val params = input.parameters
        val state = params.state
            ?: return AuthnResponseResult.ValidationError("state", params.state)
                .also { Napier.w("Invalid state: ${params.state}") }
        val authnRequest = stateToAuthnRequestStore.get(state)
            ?: return AuthnResponseResult.ValidationError("state", state)
                .also { Napier.w("State not associated with authn request: $state") }

        val responseType = authnRequest.responseType
        if (responseType?.contains(OpenIdConstants.VP_TOKEN) == true) {
            val expectedNonce = authnRequest.nonce
                ?: return AuthnResponseResult.ValidationError("state", state)
                    .also { Napier.w("State not associated with nonce: $state") }
            val presentationSubmission = params.presentationSubmission
                ?: return AuthnResponseResult.ValidationError("presentation_submission", state)
                    .also { Napier.w("presentation_submission empty") }
            val descriptors = presentationSubmission.descriptorMap
                ?: return AuthnResponseResult.ValidationError("presentation_submission", state)
                    .also { Napier.w("presentation_submission contains no descriptors") }
            val verifiablePresentation = params.vpToken
                ?: return AuthnResponseResult.ValidationError("vp_token is null", state)
                    .also { Napier.w("No VP in response") }

            val validationResults = descriptors.map { descriptor ->
                val relatedPresentation = JsonPath(descriptor.cumulativeJsonPath)
                    .query(verifiablePresentation).first().value
                val result = runCatching {
                    verifyPresentationResult(
                        descriptor,
                        relatedPresentation,
                        expectedNonce,
                        input,
                        authnRequest.clientId,
                        authnRequest.responseUrl
                    )
                }.getOrElse {
                    Napier.w("Invalid presentation format: $relatedPresentation", it)
                    return AuthnResponseResult.ValidationError("Invalid presentation", state)
                }
                result.mapToAuthnResponseResult(state)
            }
            return validationResults.firstOrList()
        }

        if (responseType?.contains(OpenIdConstants.ID_TOKEN) == true) {
            val idToken = params.idToken?.let { idToken ->
                catching {
                    extractValidatedIdToken(idToken)
                }.getOrElse {
                    return AuthnResponseResult.ValidationError("idToken", state)
                }
            } ?: return AuthnResponseResult.ValidationError("idToken", state)
                .also { Napier.w("State not associated with response type: $state") }
            return AuthnResponseResult.IdToken(idToken, state)
        }

        return AuthnResponseResult.Error("Neither id_token nor vp_token", state)
    }

    private fun List<AuthnResponseResult>.firstOrList(): AuthnResponseResult =
        if (size == 1) this[0]
        else AuthnResponseResult.VerifiablePresentationValidationResults(this)

    @Throws(IllegalArgumentException::class, CancellationException::class)
    private suspend fun extractValidatedIdToken(idTokenJws: String): IdToken {
        val jwsSigned = JwsSigned.Companion.deserialize<IdToken>(
            IdToken.Companion.serializer(), idTokenJws,
            vckJsonSerializer
        ).getOrNull()
            ?: throw IllegalArgumentException("idToken")
                .also { Napier.w("Could not parse JWS from idToken: $idTokenJws") }
        if (!verifierJwsService.verifyJwsObject(jwsSigned))
            throw IllegalArgumentException("idToken")
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
        val idToken = jwsSigned.payload
        if (idToken.issuer != idToken.subject)
            throw IllegalArgumentException("idToken.iss")
                .also { Napier.d("Wrong issuer: ${idToken.issuer}, expected: ${idToken.subject}") }
        if (idToken.audience != clientIdScheme.clientId)
            throw IllegalArgumentException("idToken.aud")
                .also { Napier.d("audience not valid: ${idToken.audience}") }
        if (idToken.expiration < (clock.now() - timeLeeway))
            throw IllegalArgumentException("idToken.exp")
                .also { Napier.d("expirationDate before now: ${idToken.expiration}") }
        if (idToken.issuedAt > (clock.now() + timeLeeway))
            throw IllegalArgumentException("idToken.iat")
                .also { Napier.d("issuedAt after now: ${idToken.issuedAt}") }
        if (!nonceService.verifyAndRemoveNonce(idToken.nonce)) {
            throw IllegalArgumentException("idToken.nonce")
                .also { Napier.d("nonce not valid: ${idToken.nonce}, not known to us") }
        }
        if (idToken.subjectJwk == null)
            throw IllegalArgumentException("idToken.sub_jwk")
                .also { Napier.d("sub_jwk is null") }
        if (idToken.subject != idToken.subjectJwk!!.jwkThumbprint)
            throw IllegalArgumentException("idToken.sub")
                .also { Napier.d("subject does not equal thumbprint of sub_jwk: ${idToken.subject}") }
        return idToken
    }

    /**
     * Extract and verifies verifiable presentations, according to format defined in
     * [OpenID for VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html),
     * as referenced by [OpenID for VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).
     */
    private suspend fun verifyPresentationResult(
        descriptor: PresentationSubmissionDescriptor,
        relatedPresentation: JsonElement,
        expectedNonce: String,
        input: ResponseParametersFrom,
        clientId: String?,
        responseUrl: String?,
    ) = when (descriptor.format) {
        ClaimFormat.JWT_SD -> verifier.verifyPresentationSdJwt(
            input = SdJwtSigned.Companion.parse(relatedPresentation.jsonPrimitive.content)
                ?: throw IllegalArgumentException("relatedPresentation"),
            challenge = expectedNonce
        )

        ClaimFormat.JWT_VP -> verifier.verifyPresentationVcJwt(
            input = JwsSigned.Companion.deserialize<VerifiablePresentationJws>(
                VerifiablePresentationJws.Companion.serializer(),
                relatedPresentation.jsonPrimitive.content,
                vckJsonSerializer
            ).getOrThrow(),
            challenge = expectedNonce
        )

        ClaimFormat.MSO_MDOC -> {
            val mdocGeneratedNonce = (input as? ResponseParametersFrom.JweDecrypted)?.jweDecrypted
                ?.header?.agreementPartyUInfo?.decodeToByteArrayOrNull(Base64UrlStrict)?.decodeToString()
            verifier.verifyPresentationIsoMdoc(
                input = relatedPresentation.jsonPrimitive.content.decodeToByteArray(Base64UrlStrict)
                    .let { DeviceResponse.Companion.deserialize(it).getOrThrow() },
                challenge = expectedNonce,
                verifyDocument = verifyDocument(mdocGeneratedNonce, clientId, responseUrl, expectedNonce)
            )
        }

        else -> throw IllegalArgumentException("descriptor.format")
    }

    /**
     * Performs verification of the [at.asitplus.wallet.lib.iso.SessionTranscript] and [at.asitplus.wallet.lib.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024, if required (i.e. response is encrypted)
     */
    @Throws(IllegalArgumentException::class)
    private fun verifyDocument(
        mdocGeneratedNonce: String?,
        clientId: String?,
        responseUrl: String?,
        expectedNonce: String,
    ): (MobileSecurityObject, Document) -> Boolean = { mso, document ->
        val deviceSignature = document.deviceSigned.deviceAuth.deviceSignature ?: run {
            Napier.w("DeviceSignature is null: ${document.deviceSigned.deviceAuth}")
            throw IllegalArgumentException("deviceSignature")
        }

        val walletKey = mso.deviceKeyInfo.deviceKey
        if (mdocGeneratedNonce != null && clientId != null && responseUrl != null) {
            val deviceAuthentication =
                document.calcDeviceAuthentication(expectedNonce, mdocGeneratedNonce, clientId, responseUrl)
            Napier.d("Device authentication is ${deviceAuthentication.encodeToString(Base16())}")
            verifierCoseService.verifyCose(
                deviceSignature,
                walletKey,
                detachedPayload = deviceAuthentication
            ).onFailure {
                Napier.w("DeviceSignature not verified: ${document.deviceSigned.deviceAuth}", it)
                throw IllegalArgumentException("deviceSignature")
            }
        } else {
            verifierCoseService.verifyCose(deviceSignature, walletKey).onFailure {
                Napier.w("DeviceSignature not verified: ${document.deviceSigned.deviceAuth}", it)
                throw IllegalArgumentException("deviceSignature")
            }
            val deviceSignaturePayload = deviceSignature.payload ?: run {
                Napier.w("DeviceSignature does not contain challenge")
                throw IllegalArgumentException("challenge")
            }
            if (!deviceSignaturePayload.contentEquals(expectedNonce.encodeToByteArray())) {
                Napier.w("DeviceSignature does not contain correct challenge")
                throw IllegalArgumentException("challenge")
            }
        }
        true
    }

    /**
     * Performs calculation of the [at.asitplus.wallet.lib.iso.SessionTranscript] and [at.asitplus.wallet.lib.iso.DeviceAuthentication],
     * acc. to ISO/IEC 18013-5:2021 and ISO/IEC 18013-7:2024
     */
    private fun Document.calcDeviceAuthentication(
        challenge: String,
        mdocGeneratedNonce: String,
        clientId: String,
        responseUrl: String,
    ): ByteArray {
        val clientIdToHash = ClientIdToHash(clientId = clientId, mdocGeneratedNonce = mdocGeneratedNonce)
        val responseUriToHash = ResponseUriToHash(responseUri = responseUrl, mdocGeneratedNonce = mdocGeneratedNonce)
        val sessionTranscript = SessionTranscript(
            deviceEngagementBytes = null,
            eReaderKeyBytes = null,
            handover = ByteStringWrapper(
                OID4VPHandover(
                    clientIdHash = clientIdToHash.serialize().sha256(),
                    responseUriHash = responseUriToHash.serialize().sha256(),
                    nonce = challenge
                )
            ),
        )
        val deviceAuthentication = DeviceAuthentication(
            type = "DeviceAuthentication",
            sessionTranscript = sessionTranscript,
            docType = docType,
            namespaces = deviceSigned.namespaces
        )
        return deviceAuthentication.serialize()
    }

    private fun Verifier.VerifyPresentationResult.mapToAuthnResponseResult(state: String) = when (this) {
        is Verifier.VerifyPresentationResult.InvalidStructure ->
            AuthnResponseResult.Error("parse vp failed", state)
                .also { Napier.w("VP error: $this") }

        is Verifier.VerifyPresentationResult.ValidationError ->
            AuthnResponseResult.ValidationError("vpToken", state)
                .also { Napier.w("VP error: $this") }

        is Verifier.VerifyPresentationResult.Success ->
            AuthnResponseResult.Success(vp, state)
                .also { Napier.i("VP success: $this") }

        is Verifier.VerifyPresentationResult.SuccessIso ->
            AuthnResponseResult.SuccessIso(documents, state)
                .also { Napier.i("VP success: $this") }

        is Verifier.VerifyPresentationResult.SuccessSdJwt ->
            AuthnResponseResult.SuccessSdJwt(
                sdJwtSigned = sdJwtSigned,
                verifiableCredentialSdJwt = verifiableCredentialSdJwt,
                reconstructed = reconstructedJsonObject,
                disclosures = disclosures,
                state = state
            ).also { Napier.i("VP success: $this") }
    }

}

private val PresentationSubmissionDescriptor.cumulativeJsonPath: String
    get() {
        var cummulativeJsonPath = this.path
        var descriptorIterator = this.nestedPath
        while (descriptorIterator != null) {
            cummulativeJsonPath += descriptorIterator.path.substring(1)
            descriptorIterator = descriptorIterator.nestedPath
        }
        return cummulativeJsonPath
    }
