package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.FormatContainerJwt
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.jws.VerifierJwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.DurationUnit
import kotlin.time.toDuration


/**
 * Combines Verifiable Presentations with OpenId Connect
 * [Implements OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).
 *
 * The [verifier] creates the Authentication Request, and the [holder] creates the Authentication Response.
 */
class OidcSiopProtocol(
    private val holder: Holder? = null,
    private val verifier: Verifier? = null,
    private val agentPublicKey: JsonWebKey,
    private val jwsService: JwsService,
    private val verifierJwsService: VerifierJwsService,
    private val relyingPartyChallenge: String = uuid4().toString(),
    private val walletUrl: String = "https://wallet.a-sit.at/mobile",
    private val relyingPartyUrl: String = "https://wallet.a-sit.at/verifier",
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System
) {

    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private var stateOfRelyingParty = uuid4().toString()

    companion object {
        fun newVerifierInstance(
            verifier: Verifier,
            cryptoService: CryptoService,
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            jwsService: JwsService = DefaultJwsService(cryptoService),
            relyingPartyChallenge: String = uuid4().toString(),
            relyingPartyUrl: String = "https://wallet.a-sit.at/verifier",
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System
        ) = OidcSiopProtocol(
            verifier = verifier,
            agentPublicKey = cryptoService.toJsonWebKey(),
            jwsService = jwsService,
            verifierJwsService = verifierJwsService,
            relyingPartyChallenge = relyingPartyChallenge,
            relyingPartyUrl = relyingPartyUrl,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock
        )

        fun newHolderInstance(
            holder: Holder,
            cryptoService: CryptoService,
            jwsService: JwsService = DefaultJwsService(cryptoService),
            walletUrl: String = "https://wallet.a-sit.at/wallet",
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System
        ) = OidcSiopProtocol(
            holder = holder,
            agentPublicKey = cryptoService.toJsonWebKey(),
            jwsService = jwsService,
            verifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            walletUrl = walletUrl,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock
        )
    }

    /**
     * Creates a OIDC [AuthenticationRequest] URL to call the Wallet Implementation (acting as SIOP V2)
     */
    fun createAuthnRequest(): String {
        val metadata = RelyingPartyMetadata(
            redirectUris = arrayOf(relyingPartyUrl),
            jsonWebKeySet = JsonWebKeySet(arrayOf(agentPublicKey)),
            subjectSyntaxTypesSupported = arrayOf("urn:ietf:params:oauth:jwk-thumbprint", "did:key"),
            vpFormats = FormatHolder(
                jwtVp = FormatContainerJwt(algorithms = arrayOf(JwsAlgorithm.ES256.text)),
            ),
        )
        return AuthenticationRequest(
            url = walletUrl,
            params = AuthenticationRequestParameters(
                responseType = "id_token vp_token",
                clientId = relyingPartyUrl,
                redirectUri = relyingPartyUrl,
                scope = "openid profile",
                state = stateOfRelyingParty,
                nonce = relyingPartyChallenge,
                clientMetadata = metadata,
                idTokenType = IdTokenType.ATTESTER_SIGNED,
                presentationDefinition = PresentationDefinition(
                    id = uuid4().toString(),
                    formats = FormatHolder(
                        jwtVp = FormatContainerJwt(algorithms = arrayOf(JwsAlgorithm.ES256.text))
                    ),
                    inputDescriptors = arrayOf(
                        InputDescriptor(
                            id = uuid4().toString(),
                            format = FormatHolder(
                                jwtVp = FormatContainerJwt(algorithms = arrayOf(JwsAlgorithm.ES256.text))
                            ),
                            schema = arrayOf(SchemaReference("https://example.com")),
                            constraints = Constraint(
                                fields = arrayOf(
                                    ConstraintField(
                                        path = arrayOf("$.type"),
                                        filter = ConstraintFilter(
                                            type = "string",
                                            pattern = "IDCardCredential",
                                        )
                                    )
                                ),
                            ),
                        )
                    ),
                ),
            ),
        ).toUrl()
    }

    /**
     * Pass in the serialized [AuthenticationRequest] to create an [AuthenticationResponse]
     */
    suspend fun createAuthnResponse(it: String): String? {
        val request = AuthenticationRequest.parseUrl(it)
            ?: return null
                .also { Napier.w("Could not parse authentication request") }
        // TODO could also contain "request_uri"
        // TODO could also contain "response_mode=post"
        stateOfRelyingParty = request.params.state
        val audience = request.params.clientMetadata?.jsonWebKeySet?.keys?.get(0)?.identifier
            ?: return null
                .also { Napier.w("Could not parse audience") }
        if ("urn:ietf:params:oauth:jwk-thumbprint" !in request.params.clientMetadata.subjectSyntaxTypesSupported)
            return null
                .also { Napier.w("Incompatible subject syntax types algorithms") }
        if (request.params.clientId != request.params.redirectUri)
            return null
                .also { Napier.w("client_id does not match redirect_uri") }
        if ("id_token" !in request.params.responseType)
            return null
                .also { Napier.w("response_type is not \"id_token\"") }
        // TODO "claims" may be set by the RP to tell OP which attributes to release
        if ("vp_token" !in request.params.responseType && request.params.presentationDefinition == null)
            return null
                .also { Napier.w("vp_token not requested") }
        if (request.params.clientMetadata.vpFormats == null)
            return null
                .also { Napier.w("Incompatible subject syntax types algorithms") }
        if (request.params.clientMetadata.vpFormats.jwtVp?.algorithms?.contains(JwsAlgorithm.ES256.text) != true)
            return null
                .also { Napier.w("Incompatible JWT algorithms") }
        val vp = holder?.createPresentation(request.params.nonce, audience)
            ?: return null
                .also { Napier.w("Could not create presentation") }
        if (vp !is Holder.CreatePresentationResult.Signed)
            return null
                .also { Napier.w("Could not create presentation") }
        val now = clock.now()
        // we'll assume jwk-thumbprint
        val idToken = IdToken(
            issuer = agentPublicKey.jwkThumbprint,
            subject = agentPublicKey.jwkThumbprint,
            subjectJwk = agentPublicKey,
            audience = request.params.redirectUri,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = request.params.nonce,
        )
        val jwsPayload = idToken.serialize().encodeToByteArray()
        val jwsHeader = JwsHeader(JwsAlgorithm.ES256)
        val signedIdToken = jwsService.createSignedJwsAddingParams(jwsHeader, jwsPayload)
            ?: return null
                .also { Napier.w("Could not sign id_token") }
        val presentationSubmission = PresentationSubmission(
            id = uuid4().toString(),
            definitionId = request.params.presentationDefinition?.id ?: uuid4().toString(),
            descriptorMap = request.params.presentationDefinition?.inputDescriptors?.map {
                PresentationSubmissionDescriptor(
                    id = it.id,
                    format = ClaimFormatEnum.JWT_VP,
                    path = "$",
                    nestedPath = PresentationSubmissionDescriptor(
                        id = uuid4().toString(),
                        format = ClaimFormatEnum.JWT_VC,
                        path = "$.verifiableCredential[0]"
                    ),
                )
            }?.toTypedArray()
        )
        return AuthenticationResponse(
            url = request.params.redirectUri,
            params = AuthenticationResponseParameters(
                idToken = signedIdToken,
                state = request.params.state,
                vpToken = vp.jws,
                presentationSubmission = presentationSubmission,
            )
        ).toUrl()
    }

    sealed class AuthnResponseResult {
        data class Error(val reason: String) : AuthnResponseResult()
        data class Success(val vp: VerifiablePresentationParsed) : AuthnResponseResult()
    }

    /**
     * Validates the [AuthenticationResponse] from the wallet
     */
    fun validateAuthnResponse(it: String): AuthnResponseResult {
        val response = AuthenticationResponse.parseUrl(it)
            ?: return AuthnResponseResult.Error("url")
                .also { Napier.w("Could not parse authentication response: $it") }
        val idTokenJws = response.params.idToken
        val jwsSigned = JwsSigned.parse(idTokenJws)
            ?: return AuthnResponseResult.Error("idToken")
                .also { Napier.w("Could not parse JWS from idToken: $idTokenJws") }
        if (!verifierJwsService.verifyJwsObject(jwsSigned, idTokenJws))
            return AuthnResponseResult.Error("idToken")
                .also { Napier.w { "JWS of idToken not verified: $idTokenJws" } }
        val idToken = IdToken.deserialize(jwsSigned.payload.decodeToString())
            ?: return AuthnResponseResult.Error("idToken")
                .also { Napier.w("Could not deserialize idToken: $idTokenJws") }
        if (idToken.issuer != idToken.subject)
            return AuthnResponseResult.Error("iss")
                .also { Napier.d("Wrong issuer: ${idToken.issuer}, expected: ${idToken.subject}") }
        if (idToken.audience != relyingPartyUrl)
            return AuthnResponseResult.Error("aud")
                .also { Napier.d("audience not valid: ${idToken.audience}") }
        if (idToken.expiration < (clock.now() - timeLeeway))
            return AuthnResponseResult.Error("exp")
                .also { Napier.d("expirationDate before now: ${idToken.expiration}") }
        if (idToken.issuedAt > (clock.now() + timeLeeway))
            return AuthnResponseResult.Error("iat")
                .also { Napier.d("issuedAt after now: ${idToken.issuedAt}") }
        if (idToken.nonce != relyingPartyChallenge)
            return AuthnResponseResult.Error("nonce")
                .also { Napier.d("nonce not valid: ${idToken.nonce}, should be $relyingPartyChallenge") }
        if (idToken.subjectJwk == null)
            return AuthnResponseResult.Error("nonce")
                .also { Napier.d("sub_jwk is null") }
        if (idToken.subject != idToken.subjectJwk.jwkThumbprint)
            return AuthnResponseResult.Error("sub")
                .also { Napier.d("subject does not equal thumbprint of sub_jwk: ${idToken.subject}") }
        val vp = response.params.vpToken
            ?: return AuthnResponseResult.Error("vpToken is null")
                .also { Napier.w("No VP in response") }
        val verificationResult = verifier?.verifyPresentation(vp, relyingPartyChallenge)
            ?: return AuthnResponseResult.Error("vpToken not verified")
                .also { Napier.w("No VP parsed") }

        return when (verificationResult) {
            is Verifier.VerifyPresentationResult.InvalidStructure -> AuthnResponseResult.Error("parse vp failed")
            is Verifier.VerifyPresentationResult.Success -> AuthnResponseResult.Success(verificationResult.vp)
            is Verifier.VerifyPresentationResult.NotVerified -> AuthnResponseResult.Error("vp not verified")
        }
    }


}
