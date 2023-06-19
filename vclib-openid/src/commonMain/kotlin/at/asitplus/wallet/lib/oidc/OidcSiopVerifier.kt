package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.DefaultVerifierCryptoService
import at.asitplus.wallet.lib.agent.Verifier
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.data.dif.Constraint
import at.asitplus.wallet.lib.data.dif.ConstraintField
import at.asitplus.wallet.lib.data.dif.ConstraintFilter
import at.asitplus.wallet.lib.data.dif.FormatContainerJwt
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.SchemaReference
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.DurationUnit
import kotlin.time.toDuration


/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * The [verifier] creates the Authentication Request, see [OidcSiopWallet] for the holder.
 */
class OidcSiopVerifier(
    private val verifier: Verifier,
    private val agentPublicKey: JsonWebKey,
    private val verifierJwsService: VerifierJwsService,
    private val relyingPartyChallenge: String = uuid4().toString(),
    timeLeewaySeconds: Long = 300L,
    private val clock: Clock = Clock.System
) {

    private val timeLeeway = timeLeewaySeconds.toDuration(DurationUnit.SECONDS)
    private val relyingPartyState = uuid4().toString()

    companion object {
        fun newInstance(
            verifier: Verifier,
            cryptoService: CryptoService,
            verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
            relyingPartyChallenge: String = uuid4().toString(),
            timeLeewaySeconds: Long = 300L,
            clock: Clock = Clock.System
        ) = OidcSiopVerifier(
            verifier = verifier,
            agentPublicKey = cryptoService.toJsonWebKey(),
            verifierJwsService = verifierJwsService,
            relyingPartyChallenge = relyingPartyChallenge,
            timeLeewaySeconds = timeLeewaySeconds,
            clock = clock
        )

    }

    /**
     * Creates a OIDC [AuthenticationRequest] URL to call the Wallet Implementation (acting as SIOP V2)
     */
    fun createAuthnRequestUrl(walletUrl: String, relyingPartyUrl: String): String {
        return AuthenticationRequest(
            url = walletUrl,
            params = createAuthnRequest(relyingPartyUrl),
        ).toUrl()
    }

    /**
     * Creates [AuthenticationRequestParameters], to be encoded as query params appended to the URL of the Wallet,
     * e.g. `https://example.com?repsonse_type=...`
     *
     * Callers may serialize the result with `result.encodeToParameters().formUrlEncode()`
     */
    fun createAuthnRequest(relyingPartyUrl: String): AuthenticationRequestParameters {
        val metadata = RelyingPartyMetadata(
            redirectUris = arrayOf(relyingPartyUrl),
            jsonWebKeySet = JsonWebKeySet(arrayOf(agentPublicKey)),
            subjectSyntaxTypesSupported = arrayOf(URN_TYPE_JWK_THUMBPRINT, "did:key"),
            vpFormats = FormatHolder(
                jwtVp = FormatContainerJwt(algorithms = arrayOf(JwsAlgorithm.ES256.text)),
            ),
        )
        return AuthenticationRequestParameters(
            responseType = "$ID_TOKEN $VP_TOKEN",
            clientId = relyingPartyUrl,
            redirectUrl = relyingPartyUrl,
            scope = "openid profile",
            state = relyingPartyState,
            nonce = relyingPartyChallenge,
            clientMetadata = metadata,
            idTokenType = IdTokenType.SUBJECT_SIGNED.text,
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
        )
    }

    sealed class AuthnResponseResult {
        data class Error(val reason: String) : AuthnResponseResult()
        data class Success(val vp: VerifiablePresentationParsed) : AuthnResponseResult()
    }

    /**
     * Validates the [AuthenticationResponse] from the Wallet, where [it] is the whole URL,
     * e.g. "https://example.com#id_token=..."
     */
    fun validateAuthnResponse(it: String, relyingPartyUrl: String): AuthnResponseResult {
        val response = AuthenticationResponse.parseUrl(it)
            ?: return AuthnResponseResult.Error("url")
                .also { Napier.w("Could not parse authentication response: $it") }
        val params = response.params
        return validateAuthnResponse(params, relyingPartyUrl)
    }

    /**
     * Validates [AuthenticationResponseParameters] from the Wallet, where [relyingPartyUrl] is "our" (=the RP) URL
     */
    fun validateAuthnResponse(params: AuthenticationResponseParameters, relyingPartyUrl: String): AuthnResponseResult {
        val idTokenJws = params.idToken
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
        val vp = params.vpToken
            ?: return AuthnResponseResult.Error("vpToken is null")
                .also { Napier.w("No VP in response") }
        val verificationResult = verifier.verifyPresentation(vp, relyingPartyChallenge)

        return when (verificationResult) {
            is Verifier.VerifyPresentationResult.InvalidStructure -> AuthnResponseResult.Error("parse vp failed")
            is Verifier.VerifyPresentationResult.Success -> AuthnResponseResult.Success(verificationResult.vp)
            is Verifier.VerifyPresentationResult.NotVerified -> AuthnResponseResult.Error("vp not verified")
        }
    }


}
