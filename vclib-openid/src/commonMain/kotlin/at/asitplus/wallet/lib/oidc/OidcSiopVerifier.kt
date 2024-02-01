package at.asitplus.wallet.lib.oidc

import at.asitplus.KmmResult
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.dif.*
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ClientIdSchemes.REDIRECT_URI
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
import kotlinx.datetime.Clock
import kotlinx.serialization.encodeToString
import kotlin.time.DurationUnit
import kotlin.time.toDuration


/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * This class creates the Authentication Request, [verifier] verifies the response. See [OidcSiopWallet] for the holder.
 */
class OidcSiopVerifier(
    private val verifier: Verifier,
    private val relyingPartyUrl: String,
    private val agentPublicKey: CryptoPublicKey,
    private val jwsService: JwsService,
    private val verifierJwsService: VerifierJwsService,
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System,
    private val credentialScheme: ConstantIndex.CredentialScheme? = null,
    private val requestedAttributes: List<String>? = null,
) {

    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val challengeSet = mutableSetOf<String>()

    companion object {
        fun newInstance(
            verifier: Verifier,
            cryptoService: CryptoService,
            relyingPartyUrl: String,
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System,
            credentialScheme: ConstantIndex.CredentialScheme? = null,
            requestedAttributes: List<String>? = null,
        ) = OidcSiopVerifier(
            verifier = verifier,
            relyingPartyUrl = relyingPartyUrl,
            agentPublicKey = cryptoService.publicKey,
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock,
            credentialScheme = credentialScheme,
            requestedAttributes = requestedAttributes,
        )
    }

    private val containerJwt =
        FormatContainerJwt(algorithms = verifierJwsService.supportedAlgorithms.map { it.identifier }.toTypedArray())

    private fun getVpFormats(credentialRepresentation: ConstantIndex.CredentialRepresentation) =
        FormatHolder(
            msoMdoc = if (credentialRepresentation == ConstantIndex.CredentialRepresentation.ISO_MDOC) containerJwt else null,
            jwtVp = containerJwt,
        )

    private fun getMetaData(credentialRepresentation: ConstantIndex.CredentialRepresentation) =
        RelyingPartyMetadata(
            redirectUris = arrayOf(relyingPartyUrl),
            jsonWebKeySet = JsonWebKeySet(arrayOf(agentPublicKey.toJsonWebKey())),
            subjectSyntaxTypesSupported = arrayOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY),
            vpFormats = getVpFormats(credentialRepresentation),
        )

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
            clientId = relyingPartyUrl,
            clientMetadataUri = clientMetadataUrl,
            requestUri = requestUrl,
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return urlBuilder.buildString()
    }

    /**
     * Creates a JWS containing signed [RelyingPartyMetadata], to be served under a `client_metadata_uri` at the Verifier.
     */
    suspend fun createSignedMetadata(credentialRepresentation: ConstantIndex.CredentialRepresentation): KmmResult<JwsSigned> =
        jwsService.createSignedJwsAddingParams(
            payload = getMetaData(credentialRepresentation).serialize().encodeToByteArray(),
            addKeyId = true
        )

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl].
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     * @param credentialRepresentation specifies the required representation, see [ConstantIndex.CredentialRepresentation]
     */
    fun createAuthnRequestUrl(
        walletUrl: String,
        responseMode: String? = null,
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        state: String? = uuid4().toString(),
    ): String {
        val urlBuilder = URLBuilder(walletUrl)
        createAuthnRequest(
            responseMode = responseMode,
            credentialRepresentation = credentialRepresentation,
            state = state,
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return urlBuilder.buildString()
    }

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl],
     * containing a JWS Authorization Request (JAR, RFC9101), containing the request parameters itself.
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     * @param credentialRepresentation specifies the required representation, see [ConstantIndex.CredentialRepresentation]
     * @param state opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    suspend fun createAuthnRequestUrlWithRequestObject(
        walletUrl: String,
        responseMode: String? = null,
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        state: String? = uuid4().toString(),
    ): KmmResult<String> {
        val urlBuilder = URLBuilder(walletUrl)
        createAuthnRequestAsRequestObject(
            responseMode = responseMode,
            credentialRepresentation = credentialRepresentation,
            state = state,
        ).getOrElse {
            return KmmResult.failure(it)
        }.encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return KmmResult.success(urlBuilder.buildString())
    }

    /**
     * Creates an JWS Authorization Request (JAR, RFC9101), wrapping the usual [AuthenticationRequestParameters].
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     * @param credentialRepresentation specifies the required representation, see [ConstantIndex.CredentialRepresentation]
     * @param state opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    suspend fun createAuthnRequestAsRequestObject(
        responseMode: String? = null,
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        state: String? = uuid4().toString(),
    ): KmmResult<AuthenticationRequestParameters> {
        val requestObject = createAuthnRequest(
            responseMode = responseMode,
            credentialRepresentation = credentialRepresentation,
            state = state,
        )
        val requestObjectSerialized = jsonSerializer.encodeToString(
            requestObject.copy(audience = relyingPartyUrl, issuer = relyingPartyUrl)
        )
        val signedJws = jwsService.createSignedJwsAddingParams(
            payload = requestObjectSerialized.encodeToByteArray(),
            addKeyId = true
        ).getOrElse {
            Napier.w("Could not sign JWS form authnRequest", it)
            return KmmResult.failure(it)
        }
        return KmmResult.success(
            AuthenticationRequestParameters(
                clientId = relyingPartyUrl,
                request = signedJws.serialize()
            )
        )
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded as query params appended to the URL of the Wallet,
     * e.g. `https://example.com?repsonse_type=...` (see [createAuthnRequestUrl])
     *
     * Callers may serialize the result with `result.encodeToParameters().formUrlEncode()`
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     * @param credentialRepresentation specifies the required representation, see [ConstantIndex.CredentialRepresentation]
     * @param state opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    fun createAuthnRequest(
        responseMode: String? = null,
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        state: String? = uuid4().toString(),
    ): AuthenticationRequestParameters {
        val typeConstraint = credentialScheme?.let {
            when (credentialRepresentation) {
                ConstantIndex.CredentialRepresentation.PLAIN_JWT -> it.vcConstraint()
                ConstantIndex.CredentialRepresentation.SD_JWT -> it.vcConstraint()
                ConstantIndex.CredentialRepresentation.ISO_MDOC -> it.isoConstraint()
            }
        }
        val attributeConstraint =
            requestedAttributes?.let { createConstraints(credentialRepresentation, it) } ?: arrayOf()
        val constraintFields = listOfNotNull(typeConstraint, *attributeConstraint).toTypedArray()
        return AuthenticationRequestParameters(
            responseType = "$ID_TOKEN $VP_TOKEN",
            clientId = relyingPartyUrl,
            redirectUrl = relyingPartyUrl,
            clientIdScheme = REDIRECT_URI,
            scope = listOfNotNull(SCOPE_OPENID, SCOPE_PROFILE, credentialScheme?.vcType).joinToString(" "),
            nonce = uuid4().toString().also { challengeSet += it },
            clientMetadata = getMetaData(credentialRepresentation),
            idTokenType = IdTokenType.SUBJECT_SIGNED.text,
            responseMode = responseMode,
            state = state,
            presentationDefinition = PresentationDefinition(
                id = uuid4().toString(),
                formats = getVpFormats(credentialRepresentation),
                inputDescriptors = arrayOf(
                    InputDescriptor(
                        id = uuid4().toString(),
                        schema = arrayOf(SchemaReference(credentialScheme?.schemaUri ?: "https://example.com")),
                        constraints = Constraint(fields = constraintFields),
                    )
                ),
            ),
        )
    }

    private fun ConstantIndex.CredentialScheme.vcConstraint() = ConstraintField(
        path = arrayOf("$.type"),
        filter = ConstraintFilter(
            type = "string",
            pattern = vcType,
        )
    )

    private fun ConstantIndex.CredentialScheme.isoConstraint() = ConstraintField(
        path = arrayOf("$.mdoc.doctype"),
        filter = ConstraintFilter(
            type = "string",
            pattern = isoDocType,
        )
    )

    private fun createConstraints(
        credentialRepresentation: ConstantIndex.CredentialRepresentation,
        attributeTypes: List<String>,
    ): Array<ConstraintField> =
        attributeTypes.map {
            if (credentialRepresentation == ConstantIndex.CredentialRepresentation.ISO_MDOC)
                ConstraintField(path = arrayOf("\$.mdoc.$it"), intentToRetain = false)
            else
                ConstraintField(path = arrayOf("\$.$it"))
        }.toTypedArray()


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
         * Successfully decoded and validated the response from the Wallet (W3C credential)
         */
        data class Success(val vp: VerifiablePresentationParsed, val state: String?) : AuthnResponseResult()

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
        data class SuccessIso(val document: IsoDocumentParsed, val state: String?) : AuthnResponseResult()
    }

    /**
     * Validates the OIDC Authentication Response from the Wallet, where [content] are the HTTP POST encoded
     * [AuthenticationResponseParameters], e.g. `id_token=...&vp_token=...`
     */
    fun validateAuthnResponseFromPost(content: String): AuthnResponseResult {
        val params: AuthenticationResponseParameters = content.decodeFromPostBody()
            ?: return AuthnResponseResult.Error("content", null)
                .also { Napier.w("Could not parse authentication response: $it") }
        return validateAuthnResponse(params)
    }

    /**
     * Validates the OIDC Authentication Response from the Wallet, where [url] is the whole URL, containing the
     * [AuthenticationResponseParameters] as the fragment, e.g. `https://example.com#id_token=...`
     */
    fun validateAuthnResponse(url: String): AuthnResponseResult {
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
    fun validateAuthnResponse(params: AuthenticationResponseParameters): AuthnResponseResult {
        val idTokenJws = params.idToken
        val jwsSigned = JwsSigned.parse(idTokenJws)
            ?: return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w("Could not parse JWS from idToken: $idTokenJws") }
        if (!verifierJwsService.verifyJwsObject(jwsSigned))
            return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
        val idToken = IdToken.deserialize(jwsSigned.payload.decodeToString())
            ?: return AuthnResponseResult.ValidationError("idToken", params.state)
                .also { Napier.w("Could not deserialize idToken: $idTokenJws") }
        if (idToken.issuer != idToken.subject)
            return AuthnResponseResult.ValidationError("iss", params.state)
                .also { Napier.d("Wrong issuer: ${idToken.issuer}, expected: ${idToken.subject}") }
        if (idToken.audience != relyingPartyUrl)
            return AuthnResponseResult.ValidationError("aud", params.state)
                .also { Napier.d("audience not valid: ${idToken.audience}") }
        if (idToken.expiration < (clock.now() - timeLeeway))
            return AuthnResponseResult.ValidationError("exp", params.state)
                .also { Napier.d("expirationDate before now: ${idToken.expiration}") }
        if (idToken.issuedAt > (clock.now() + timeLeeway))
            return AuthnResponseResult.ValidationError("iat", params.state)
                .also { Napier.d("issuedAt after now: ${idToken.issuedAt}") }
        if (!challengeSet.remove(idToken.nonce))
            return AuthnResponseResult.ValidationError("nonce", params.state)
                .also { Napier.d("nonce not valid: ${idToken.nonce}, not known to us") }
        if (idToken.subjectJwk == null)
            return AuthnResponseResult.ValidationError("nonce", params.state)
                .also { Napier.d("sub_jwk is null") }
        if (idToken.subject != idToken.subjectJwk.jwkThumbprint)
            return AuthnResponseResult.ValidationError("sub", params.state)
                .also { Napier.d("subject does not equal thumbprint of sub_jwk: ${idToken.subject}") }

        val presentationSubmission = params.presentationSubmission
            ?: return AuthnResponseResult.ValidationError("presentation_submission", params.state)
                .also { Napier.w("presentation_submission empty") }
        val descriptor = presentationSubmission.descriptorMap?.get(0)
            ?: return AuthnResponseResult.ValidationError("presentation_submission", params.state)
                .also { Napier.w("presentation_submission contains no descriptors") }
        val vp = params.vpToken
            ?: return AuthnResponseResult.ValidationError("vp_token is null", params.state)
                .also { Napier.w("No VP in response") }
        val format = descriptor.format

        val result = when (format) {
            ClaimFormatEnum.JWT_VP -> verifier.verifyPresentation(vp, idToken.nonce)
            ClaimFormatEnum.MSO_MDOC -> verifier.verifyPresentation(vp, idToken.nonce)
            ClaimFormatEnum.JWT_SD -> verifier.verifyPresentation(vp, idToken.nonce)
            else -> null
        } ?: return AuthnResponseResult.ValidationError("descriptor format not known", params.state)
            .also { Napier.w("Descriptor format not known: $format") }

        return when (result) {
            is Verifier.VerifyPresentationResult.InvalidStructure -> {
                Napier.w("VP error: $result")
                AuthnResponseResult.Error("parse vp failed", params.state)
            }

            is Verifier.VerifyPresentationResult.Success -> {
                Napier.i("VP success: $result")
                AuthnResponseResult.Success(result.vp, params.state)
            }

            is Verifier.VerifyPresentationResult.NotVerified -> {
                Napier.w("VP error: $result")
                AuthnResponseResult.ValidationError("vpToken", params.state)
            }

            is Verifier.VerifyPresentationResult.SuccessIso -> {
                Napier.i("VP success: $result")
                AuthnResponseResult.SuccessIso(result.document, params.state)
            }

            is Verifier.VerifyPresentationResult.SuccessSdJwt -> {
                Napier.i("VP success: $result")
                AuthnResponseResult.SuccessSdJwt(result.sdJwt, result.disclosures, params.state)
            }
        }
    }


}
