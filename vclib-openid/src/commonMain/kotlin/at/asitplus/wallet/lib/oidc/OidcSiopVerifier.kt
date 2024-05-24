package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JsonWebKeySet
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.crypto.datatypes.pki.CertificateChain
import at.asitplus.crypto.datatypes.pki.leaf
import at.asitplus.jsonpath.JsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.jsonpath.core.NormalizedJsonPathSegment
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.FormatContainerJwt
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ClientIdScheme.REDIRECT_URI
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ClientIdScheme.VERIFIER_ATTESTATION
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ClientIdScheme.X509_SAN_DNS
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.PREFIX_DID_KEY
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_OPENID
import at.asitplus.wallet.lib.oidc.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import at.asitplus.wallet.lib.oidvci.decodeFromPostBody
import at.asitplus.wallet.lib.oidvci.decodeFromUrlQuery
import at.asitplus.wallet.lib.oidvci.encodeToParameters
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import io.ktor.http.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.DurationUnit
import kotlin.time.toDuration


/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * This class creates the Authentication Request, [verifier] verifies the response. See [OidcSiopWallet] for the holder.
 */
class OidcSiopVerifier private constructor(
    private val verifier: Verifier,
    private val relyingPartyUrl: String?,
    private val responseUrl: String?,
    private val agentPublicKey: CryptoPublicKey,
    private val jwsService: JwsService,
    private val verifierJwsService: VerifierJwsService,
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
    /**
     * Verifier Attestation JWT (from OID4VP) to include (in header `jwt`) when creating request objects as JWS,
     * to allow the Wallet to verify the authenticity of this Verifier.
     */
    private val attestationJwt: JwsSigned?,
    private val x5c: CertificateChain?,
    private val clientIdScheme: OpenIdConstants.ClientIdScheme
) {

    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val challengeMutex = Mutex()
    private val challengeSet = mutableSetOf<String>()

    companion object {
        fun newInstance(
            verifier: Verifier,
            cryptoService: CryptoService,
            relyingPartyUrl: String,
            responseUrl: String? = null,
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System,
            attestationJwt: JwsSigned,
        ) = OidcSiopVerifier(
            verifier = verifier,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = responseUrl,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock,
            attestationJwt = attestationJwt,
            x5c = null,
            clientIdScheme = VERIFIER_ATTESTATION
        )

        fun newInstance(
            verifier: Verifier,
            cryptoService: CryptoService,
            relyingPartyUrl: String?,
            responseUrl: String? = null,
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System,
            x5c: CertificateChain,
        ) = OidcSiopVerifier(
            verifier = verifier,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = responseUrl,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock,
            attestationJwt = null,
            clientIdScheme = X509_SAN_DNS,
            x5c = x5c
        )


        fun newInstance(
            verifier: Verifier,
            cryptoService: CryptoService,
            relyingPartyUrl: String,
            responseUrl: String? = null,
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System,
            clientIdScheme: OpenIdConstants.ClientIdScheme = REDIRECT_URI,
        ) = OidcSiopVerifier(
            verifier = verifier,
            relyingPartyUrl = relyingPartyUrl,
            responseUrl = responseUrl,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock,
            attestationJwt = null,
            clientIdScheme = clientIdScheme,
            x5c = null
        )
    }

    private val containerJwt =
        FormatContainerJwt(algorithms = verifierJwsService.supportedAlgorithms.map { it.identifier })

    private val metadata by lazy {
        RelyingPartyMetadata(
            redirectUris = relyingPartyUrl?.let { listOf(it) },
            jsonWebKeySet = JsonWebKeySet(listOf(agentPublicKey.toJsonWebKey())),
            subjectSyntaxTypesSupported = setOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY),
            vpFormats = FormatHolder(
                msoMdoc = containerJwt,
                jwtVp = containerJwt,
                jwtSd = containerJwt,
            )
        )
    }

    /**
     * Create a URL to be displayed as a static QR code for Wallet initiation.
     * URL is the [walletUrl], with query parameters appended for [relyingPartyUrl], [clientMetadataUrl], [requestUrl].
     */
    fun createQrCodeUrl(
        walletUrl: String,
        clientMetadataUrl: String,
        requestUrl: String,
    ): String {
        val urlBuilder = URLBuilder(walletUrl)
        AuthenticationRequestParameters(
            clientId = x5c?.let { it.leaf.tbsCertificate.subjectAlternativeNames?.dnsNames?.firstOrNull() }
                ?: relyingPartyUrl,
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
    suspend fun createSignedMetadata(): KmmResult<JwsSigned> = jwsService.createSignedJwsAddingParams(
        payload = metadata.serialize().encodeToByteArray(),
        addKeyId = true,
        addX5c = false
    )

    data class RequestOptions(
        /**
         * Response mode to request, see [OpenIdConstants.ResponseMode]
         */
        val responseMode: OpenIdConstants.ResponseMode? = null,
        /**
         * Required representation, see [ConstantIndex.CredentialRepresentation]
         */
        val representation: ConstantIndex.CredentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
        /**
         * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
         */
        val state: String? = uuid4().toString(),
        /**
         * Credential type to request, or `null` to make no restrictions
         */
        val credentialScheme: ConstantIndex.CredentialScheme? = null,
        /**
         * List of attributes that shall be requested explicitly (selective disclosure),
         * or `null` to make no restrictions
         */
        val requestedAttributes: List<String>? = null,
        /**
         * Optional URL to include [metadata] by reference instead of by value (directly embedding in authn request)
         */
        val clientMetadataUrl: String? = null,
    )

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl].
     */
    suspend fun createAuthnRequestUrl(
        walletUrl: String,
        requestOptions: RequestOptions = RequestOptions(),
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
        requestOptions: RequestOptions = RequestOptions()
    ): KmmResult<String> {
        val jar = createAuthnRequestAsSignedRequestObject(requestOptions).getOrElse {
            return KmmResult.failure(it)
        }
        val urlBuilder = URLBuilder(walletUrl)
        AuthenticationRequestParameters(
            clientId = relyingPartyUrl,
            request = jar.serialize(),
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return KmmResult.success(urlBuilder.buildString())
    }

    /**
     * Creates an JWS Authorization Request (JAR, RFC9101), wrapping the usual [AuthenticationRequestParameters].
     *
     * To use this for an Authentication Request with `request_uri`, use the following code,
     * `jar` being the result of this function:
     * ```
     * val urlToSendToWallet = io.ktor.http.URLBuilder(walletUrl).apply {
     *    parameters.append("client_id", relyingPartyUrl)
     *    parameters.append("request_uri", requestUrl)
     * }.buildString()
     * // on an GET to requestUrl, return `jar.serialize()`
     * ```
     */
    suspend fun createAuthnRequestAsSignedRequestObject(
        requestOptions: RequestOptions = RequestOptions(),
    ): KmmResult<JwsSigned> {
        val requestObject = createAuthnRequest(requestOptions)
        val requestObjectSerialized = jsonSerializer.encodeToString(
            requestObject.copy(audience = relyingPartyUrl, issuer = relyingPartyUrl)
        )
        val signedJws = jwsService.createSignedJwsAddingParams(
            header = JwsHeader(
                algorithm = jwsService.algorithm,
                attestationJwt = attestationJwt?.serialize(),
                certificateChain = x5c
            ),
            payload = requestObjectSerialized.encodeToByteArray(),
            addJsonWebKey = x5c == null
        ).getOrElse {
            Napier.w("Could not sign JWS form authnRequest", it)
            return KmmResult.failure(it)
        }
        return KmmResult.success(signedJws)
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded as query params appended to the URL of the Wallet,
     * e.g. `https://example.com?repsonse_type=...` (see [createAuthnRequestUrl])
     *
     * Callers may serialize the result with `result.encodeToParameters().formUrlEncode()`
     */
    suspend fun createAuthnRequest(
        requestOptions: RequestOptions = RequestOptions(),
    ) = AuthenticationRequestParameters(
        responseType = "$ID_TOKEN $VP_TOKEN",
        clientId = buildClientId(),
        redirectUrl = requestOptions.buildRedirectUrl(),
        responseUrl = responseUrl,
        clientIdScheme = clientIdScheme,
        scope = requestOptions.buildScope(),
        nonce = uuid4().toString().also { challengeMutex.withLock { challengeSet += it } },
        clientMetadata = requestOptions.clientMetadataUrl?.let { null } ?: metadata,
        clientMetadataUri = requestOptions.clientMetadataUrl,
        idTokenType = IdTokenType.SUBJECT_SIGNED.text,
        responseMode = requestOptions.responseMode,
        state = requestOptions.state,
        presentationDefinition = PresentationDefinition(
            id = uuid4().toString(),
            formats = requestOptions.representation.toFormatHolder(),
            inputDescriptors = listOf(
                requestOptions.toInputDescriptor()
            ),
        ),
    )

    private fun RequestOptions.buildScope() = listOfNotNull(SCOPE_OPENID, SCOPE_PROFILE, credentialScheme?.vcType)
        .joinToString(" ")

    private fun buildClientId() = (x5c?.let { it.leaf.tbsCertificate.subjectAlternativeNames?.dnsNames?.firstOrNull() }
        ?: relyingPartyUrl)

    private fun RequestOptions.buildRedirectUrl() = if ((responseMode == OpenIdConstants.ResponseMode.DIRECT_POST)
        || (responseMode == OpenIdConstants.ResponseMode.DIRECT_POST_JWT)
    ) null else relyingPartyUrl

    private fun RequestOptions.toInputDescriptor() = InputDescriptor(
        id = credentialScheme?.let {
            when (representation) {
                /**
                 * doctype is not really an attribute that can be presented,
                 * encoding it into the descriptor id as in the following non-normative example fow now:
                 * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.3.1-4
                 */
                ConstantIndex.CredentialRepresentation.ISO_MDOC -> it.isoDocType
                else -> null
            }
        } ?: uuid4().toString(),
        schema = listOfNotNull(credentialScheme?.schemaUri?.let { SchemaReference(it) }),
        constraints = toConstraint(),
    )

    private fun RequestOptions.toConstraint() =
        Constraint(fields = (toAttributeConstraints() + toTypeConstraint()).filterNotNull())

    private fun RequestOptions.toAttributeConstraints() =
        requestedAttributes?.createConstraints(representation, credentialScheme)
            ?: listOf()

    private fun RequestOptions.toTypeConstraint() = credentialScheme?.let {
        when (representation) {
            ConstantIndex.CredentialRepresentation.PLAIN_JWT -> it.toVcConstraint()
            ConstantIndex.CredentialRepresentation.SD_JWT -> it.toVcConstraint()
            ConstantIndex.CredentialRepresentation.ISO_MDOC -> null
        }
    }

    private fun ConstantIndex.CredentialRepresentation.toFormatHolder() = when (this) {
        ConstantIndex.CredentialRepresentation.PLAIN_JWT -> FormatHolder(jwtVp = containerJwt)
        ConstantIndex.CredentialRepresentation.SD_JWT -> FormatHolder(jwtSd = containerJwt)
        ConstantIndex.CredentialRepresentation.ISO_MDOC -> FormatHolder(msoMdoc = containerJwt)
    }

    private fun ConstantIndex.CredentialScheme.toVcConstraint() = ConstraintField(
        path = listOf("$.type"),
        filter = ConstraintFilter(
            type = "string",
            pattern = vcType,
        )
    )

    private fun List<String>.createConstraints(
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        credentialScheme: ConstantIndex.CredentialScheme?,
    ): Collection<ConstraintField> = map {
        if (credentialRepresentation == ConstantIndex.CredentialRepresentation.ISO_MDOC)
            credentialScheme.toConstraintField(it)
        else
            ConstraintField(path = listOf("\$[${it.quote()}]"))
    }

    private fun ConstantIndex.CredentialScheme?.toConstraintField(attributeType: String) = ConstraintField(
        path = listOf(
            NormalizedJsonPath(
                NormalizedJsonPathSegment.NameSegment(this?.isoNamespace ?: "mdoc"),
                NormalizedJsonPathSegment.NameSegment(attributeType),
            ).toString()
        ),
        intentToRetain = false
    )


    sealed class AuthnResponseResult {
        /**
         * Error in parsing the URL or content itself, before verifying the contents of the OpenId response
         */
        data class Error(val reason: String, val state: String?) : AuthnResponseResult()

        /**
         * Error when validating the `vpToken` or `idToken`
         */
        data class ValidationError(val field: String, val state: String?) : AuthnResponseResult()

        /**
         * Validation results of all returned verifiable presentations
         */
        data class VerifiablePresentationValidationResults(val validationResults: List<AuthnResponseResult>) :
            AuthnResponseResult()

        /**
         * Successfully decoded and validated the response from the Wallet (W3C credential)
         */
        data class Success(val vp: VerifiablePresentationParsed, val state: String?) :
            AuthnResponseResult()

        /**
         * Successfully decoded and validated the response from the Wallet (W3C credential in SD-JWT)
         */
        data class SuccessSdJwt(
            val sdJwt: VerifiableCredentialSdJwt,
            val disclosures: List<SelectiveDisclosureItem>,
            val state: String?,
        ) : AuthnResponseResult()

        /**
         * Successfully decoded and validated the response from the Wallet (ISO credential)
         */
        data class SuccessIso(val document: IsoDocumentParsed, val state: String?) :
            AuthnResponseResult()
    }

    /**
     * Validates the OIDC Authentication Response from the Wallet, where [content] are the HTTP POST encoded
     * [AuthenticationResponseParameters], e.g. `id_token=...&vp_token=...`
     */
    suspend fun validateAuthnResponseFromPost(content: String): AuthnResponseResult {
        val params: AuthenticationResponseParameters = content.decodeFromPostBody()
            ?: return AuthnResponseResult.Error("content", null)
                .also { Napier.w("Could not parse authentication response: $it") }
        return validateAuthnResponse(params)
    }

    /**
     * Validates the OIDC Authentication Response from the Wallet, where [url] is the whole URL, containing the
     * [AuthenticationResponseParameters] as the fragment, e.g. `https://example.com#id_token=...`
     */
    suspend fun validateAuthnResponse(url: String): AuthnResponseResult {
        val params = kotlin.runCatching {
            val parsedUrl = Url(url)
            if (parsedUrl.fragment.isNotEmpty())
                parsedUrl.fragment.decodeFromPostBody<AuthenticationResponseParameters>()
            else
                parsedUrl.encodedQuery.decodeFromUrlQuery<AuthenticationResponseParameters>()
        }.getOrNull()
            ?: return AuthnResponseResult.Error("url not parsable", null)
                .also { Napier.w("Could not parse authentication response: $url") }
        return validateAuthnResponse(params)
    }

    /**
     * Validates [AuthenticationResponseParameters] from the Wallet
     */
    suspend fun validateAuthnResponse(params: AuthenticationResponseParameters): AuthnResponseResult {
        if (params.response != null) {
            JwsSigned.parse(params.response).getOrNull()?.let { jarmResponse ->
                if (!verifierJwsService.verifyJwsObject(jarmResponse)) {
                    return AuthnResponseResult.ValidationError("response", params.state)
                        .also { Napier.w { "JWS of response not verified: ${params.response}" } }
                }
                AuthenticationResponseParameters.deserialize(jarmResponse.payload.decodeToString())
                    .getOrNull()?.let { return validateAuthnResponse(it) }
            }
        }
        val idTokenJws = params.idToken
            ?: return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w("Could not parse idToken: $params") }
        val jwsSigned = JwsSigned.parse(idTokenJws).getOrNull()
            ?: return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w("Could not parse JWS from idToken: $idTokenJws") }
        if (!verifierJwsService.verifyJwsObject(jwsSigned))
            return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
        val idToken = IdToken.deserialize(jwsSigned.payload.decodeToString()).getOrElse { ex ->
            return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w("Could not deserialize idToken: $idTokenJws", ex) }
        }
        if (idToken.issuer != idToken.subject)
            return AuthnResponseResult.ValidationError("iss", params.state)
                .also { Napier.d("Wrong issuer: ${idToken.issuer}, expected: ${idToken.subject}") }
        if (idToken.audience != relyingPartyUrl ?: x5c?.leaf?.tbsCertificate?.subjectAlternativeNames?.dnsNames?.firstOrNull())
            return AuthnResponseResult.ValidationError("aud", params.state)
                .also { Napier.d("audience not valid: ${idToken.audience}") }
        if (idToken.expiration < (clock.now() - timeLeeway))
            return AuthnResponseResult.ValidationError("exp", params.state)
                .also { Napier.d("expirationDate before now: ${idToken.expiration}") }
        if (idToken.issuedAt > (clock.now() + timeLeeway))
            return AuthnResponseResult.ValidationError("iat", params.state)
                .also { Napier.d("issuedAt after now: ${idToken.issuedAt}") }
        challengeMutex.withLock {
            if (!challengeSet.remove(idToken.nonce))
                return AuthnResponseResult.ValidationError("nonce", params.state)
                    .also { Napier.d("nonce not valid: ${idToken.nonce}, not known to us") }
        }
        if (idToken.subjectJwk == null)
            return AuthnResponseResult.ValidationError("nonce", params.state)
                .also { Napier.d("sub_jwk is null") }
        if (idToken.subject != idToken.subjectJwk.jwkThumbprint)
            return AuthnResponseResult.ValidationError("sub", params.state)
                .also { Napier.d("subject does not equal thumbprint of sub_jwk: ${idToken.subject}") }

        val presentationSubmission = params.presentationSubmission
            ?: return AuthnResponseResult.ValidationError("presentation_submission", params.state)
                .also { Napier.w("presentation_submission empty") }
        val descriptors = presentationSubmission.descriptorMap
            ?: return AuthnResponseResult.ValidationError("presentation_submission", params.state)
                .also { Napier.w("presentation_submission contains no descriptors") }
        val verifiablePresentation = params.vpToken
            ?: return AuthnResponseResult.ValidationError("vp_token is null", params.state)
                .also { Napier.w("No VP in response") }

        val validationResults = descriptors.map { descriptor ->
            val relatedPresentation =
                JsonPath(descriptor.cumulativeJsonPath).query(verifiablePresentation).first().value

            val result = runCatching {
                when (descriptor.format) {
                    ClaimFormatEnum.JWT_VP -> verifyJwtVpResult(relatedPresentation, idToken)
                    ClaimFormatEnum.JWT_SD -> verifyJwtSdResult(relatedPresentation, idToken)
                    ClaimFormatEnum.MSO_MDOC -> verifyMsoMdocResult(relatedPresentation, idToken)
                    else -> throw IllegalArgumentException()
                }
            }.getOrElse {
                return AuthnResponseResult.ValidationError("Invalid presentation format", params.state)
                    .also { Napier.w("Invalid presentation format: $relatedPresentation") }
            }
            when (result) {
                is Verifier.VerifyPresentationResult.InvalidStructure ->
                    AuthnResponseResult.Error("parse vp failed", params.state)
                        .also { Napier.w("VP error: $result") }

                is Verifier.VerifyPresentationResult.Success ->
                    AuthnResponseResult.Success(result.vp, params.state)
                        .also { Napier.i("VP success: $result") }

                is Verifier.VerifyPresentationResult.NotVerified ->
                    AuthnResponseResult.ValidationError("vpToken", params.state)
                        .also { Napier.w("VP error: $result") }

                is Verifier.VerifyPresentationResult.SuccessIso ->
                    AuthnResponseResult.SuccessIso(result.document, params.state)
                        .also { Napier.i("VP success: $result") }

                is Verifier.VerifyPresentationResult.SuccessSdJwt ->
                    AuthnResponseResult.SuccessSdJwt(
                        result.sdJwt,
                        result.disclosures,
                        params.state
                    )
                        .also { Napier.i("VP success: $result") }
            }
        }

        return if (validationResults.size != 1) AuthnResponseResult.VerifiablePresentationValidationResults(
            validationResults = validationResults
        ) else validationResults[0]
    }

    private fun verifyMsoMdocResult(
        relatedPresentation: JsonElement,
        idToken: IdToken
    ) = when (relatedPresentation) {
        // must be a string
        // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.2.5-1
        is JsonPrimitive -> verifier.verifyPresentation(relatedPresentation.content, idToken.nonce)
        else -> throw IllegalArgumentException()
    }

    private fun verifyJwtSdResult(
        relatedPresentation: JsonElement,
        idToken: IdToken
    ) = when (relatedPresentation) {
        // must be a string
        // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.3.5-1
        is JsonPrimitive -> verifier.verifyPresentation(relatedPresentation.content, idToken.nonce)
        else -> throw IllegalArgumentException()
    }

    private fun verifyJwtVpResult(
        relatedPresentation: JsonElement,
        idToken: IdToken
    ) = when (relatedPresentation) {
        // must be a string
        // source: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1.1.5-1
        is JsonPrimitive -> verifier.verifyPresentation(relatedPresentation.content, idToken.nonce)
        else -> throw IllegalArgumentException()
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
