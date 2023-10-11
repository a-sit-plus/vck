package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.JwsAlgorithm
import at.asitplus.crypto.datatypes.jws.JwsHeader
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.data.dif.*
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.NAMESPACE_MDL
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
            agentPublicKey = cryptoService.toPublicKey(),
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock,
            credentialScheme = credentialScheme,
            requestedAttributes = requestedAttributes,
        )
    }

    /**
     * Creates an OIDC Authentication Request, encoded as query parameters to the [walletUrl].
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     */
    fun createAuthnRequestUrl(
        walletUrl: String,
        responseMode: String? = null,
        state: String? = uuid4().toString(),
    ): String {
        val urlBuilder = URLBuilder(walletUrl)
        createAuthnRequest(
            responseMode = responseMode,
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
     * @param state opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    suspend fun createAuthnRequestUrlWithRequestObject(
        walletUrl: String,
        responseMode: String? = null,
        state: String? = uuid4().toString(),
    ): String {
        val urlBuilder = URLBuilder(walletUrl)
        createAuthnRequestAsRequestObject(
            responseMode = responseMode,
            state = state,
        ).encodeToParameters()
            .forEach { urlBuilder.parameters.append(it.key, it.value) }
        return urlBuilder.buildString()
    }

    /**
     * Creates an JWS Authorization Request (JAR, RFC9101), wrapping the usual [AuthenticationRequestParameters].
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     * @param state opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    suspend fun createAuthnRequestAsRequestObject(
        responseMode: String? = null,
        state: String? = uuid4().toString(),
    ): AuthenticationRequestParameters {
        val requestObject = createAuthnRequest(
            responseMode = responseMode,
            state = state,
        )
        val requestObjectSerialized = jsonSerializer.encodeToString(
            requestObject.copy(audience = relyingPartyUrl, issuer = relyingPartyUrl)
        )
        val signedJws = jwsService.createSignedJwsAddingParams(
            JwsHeader(algorithm = JwsAlgorithm.ES256),
            requestObjectSerialized.encodeToByteArray(),
            true
        )
        return AuthenticationRequestParameters(clientId = relyingPartyUrl, request = signedJws)
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded as query params appended to the URL of the Wallet,
     * e.g. `https://example.com?repsonse_type=...` (see [createAuthnRequestUrl])
     *
     * Callers may serialize the result with `result.encodeToParameters().formUrlEncode()`
     *
     * @param responseMode which response mode to request, see [OpenIdConstants.ResponseModes]
     * @param state opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    fun createAuthnRequest(
        responseMode: String? = null,
        state: String? = uuid4().toString(),
    ): AuthenticationRequestParameters {
        val vpFormats = FormatHolder(
            msoMdoc = if (credentialScheme?.credentialFormat == ConstantIndex.CredentialFormat.ISO_18013)
                FormatContainerJwt(algorithms = arrayOf(JwsAlgorithm.ES256.identifier)) else null,
            jwtVp = FormatContainerJwt(algorithms = arrayOf(JwsAlgorithm.ES256.identifier)),
        )
        val metadata = RelyingPartyMetadata(
            redirectUris = arrayOf(relyingPartyUrl),
            jsonWebKeySet = JsonWebKeySet(arrayOf(agentPublicKey.toJsonWebKey())),
            subjectSyntaxTypesSupported = arrayOf(URN_TYPE_JWK_THUMBPRINT, PREFIX_DID_KEY),
            vpFormats = vpFormats,
        )
        val mainConstraint = when (credentialScheme?.credentialFormat) {
            ConstantIndex.CredentialFormat.W3C_VC -> ConstraintField(
                path = arrayOf("$.type"),
                filter = ConstraintFilter(
                    type = "string",
                    pattern = credentialScheme.vcType,
                )
            )

            ConstantIndex.CredentialFormat.ISO_18013 -> ConstraintField(
                path = arrayOf("$.mdoc.doctype"),
                filter = ConstraintFilter(
                    type = "string",
                    pattern = NAMESPACE_MDL,
                )
            )

            else -> ConstraintField(
                path = arrayOf("$.type"),
                filter = ConstraintFilter(
                    type = "string",
                    pattern = "AnyCredential",
                )
            )
        }
        return AuthenticationRequestParameters(
            responseType = "$ID_TOKEN $VP_TOKEN",
            clientId = relyingPartyUrl,
            redirectUrl = relyingPartyUrl,
            clientIdScheme = REDIRECT_URI,
            scope = listOfNotNull(SCOPE_OPENID, SCOPE_PROFILE, credentialScheme?.vcType).joinToString(" "),
            nonce = uuid4().toString().also { challengeSet += it },
            clientMetadata = metadata,
            idTokenType = IdTokenType.SUBJECT_SIGNED.text,
            responseMode = responseMode,
            state = state,
            presentationDefinition = PresentationDefinition(
                id = uuid4().toString(),
                formats = vpFormats,
                inputDescriptors = arrayOf(
                    InputDescriptor(
                        id = uuid4().toString(),
                        schema = arrayOf(SchemaReference(credentialScheme?.schemaUri ?: "https://example.com")),
                        constraints = Constraint(
                            fields = (requestedAttributes?.let { createConstraints(it) } ?: arrayOf()) + mainConstraint,
                        ),
                    )
                ),
            ),
        )
    }

    private fun createConstraints(attributeTypes: List<String>): Array<ConstraintField> {
        if (credentialScheme?.credentialFormat != ConstantIndex.CredentialFormat.ISO_18013)
            return arrayOf()

        return attributeTypes.map {
            ConstraintField(
                path = arrayOf("\$.mdoc.$it"),
                intentToRetain = false,
            )
        }.toTypedArray()
    }

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
        if (!verifierJwsService.verifyJwsObject(jwsSigned, idTokenJws))
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

        val verificationResult = when (format) {
            ClaimFormatEnum.JWT_VP -> verifier.verifyPresentation(vp, idToken.nonce)
            ClaimFormatEnum.MSO_MDOC -> verifier.verifyPresentation(vp, idToken.nonce)
            else -> null
        } ?: return AuthnResponseResult.ValidationError("descriptor format not known", params.state)
            .also { Napier.w("Descriptor format not known: $format") }

        return when (verificationResult) {
            is Verifier.VerifyPresentationResult.InvalidStructure -> {
                Napier.w("VP error: $verificationResult")
                AuthnResponseResult.Error("parse vp failed", params.state)
            }

            is Verifier.VerifyPresentationResult.Success -> {
                Napier.i("VP success: $verificationResult")
                AuthnResponseResult.Success(verificationResult.vp, params.state)
            }

            is Verifier.VerifyPresentationResult.NotVerified -> {
                Napier.w("VP error: $verificationResult")
                AuthnResponseResult.ValidationError("vpToken", params.state)
            }

            is Verifier.VerifyPresentationResult.SuccessIso -> {
                Napier.i("VP success: $verificationResult")
                AuthnResponseResult.SuccessIso(verificationResult.document, params.state)
            }
        }
    }


}
