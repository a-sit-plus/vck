package at.asitplus.wallet.lib.oidc

import at.asitplus.wallet.lib.agent.CryptoService
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JsonWebKey
import at.asitplus.wallet.lib.jws.JwsAlgorithm
import at.asitplus.wallet.lib.jws.JwsHeader
import at.asitplus.wallet.lib.jws.JwsService
import at.asitplus.wallet.lib.oidc.OpenIdConstants.ID_TOKEN
import at.asitplus.wallet.lib.oidc.OpenIdConstants.URN_TYPE_JWK_THUMBPRINT
import at.asitplus.wallet.lib.oidc.OpenIdConstants.VP_TOKEN
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier
import kotlinx.datetime.Clock
import kotlin.time.Duration.Companion.seconds


/**
 * Combines Verifiable Presentations with OpenId Connect.
 * Implements [OIDC for VP](https://openid.net/specs/openid-connect-4-verifiable-presentations-1_0.html) (2023-04-21)
 * as well as [SIOP V2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) (2023-01-01).
 *
 * The [holder] creates the Authentication Response, see [OidcSiopVerifier] for the verifier.
 */
class OidcSiopWallet(
    private val holder: Holder,
    private val agentPublicKey: JsonWebKey,
    private val jwsService: JwsService,
    private val clock: Clock = Clock.System
) {

    companion object {
        fun newInstance(
            holder: Holder,
            cryptoService: CryptoService,
            jwsService: JwsService = DefaultJwsService(cryptoService),
            clock: Clock = Clock.System
        ) = OidcSiopWallet(
            holder = holder,
            agentPublicKey = cryptoService.toJsonWebKey(),
            jwsService = jwsService,
            clock = clock
        )
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
        return createAuthnResponse(request.params)
    }

    /**
     * Pass in the deserialized [AuthenticationRequestParameters], which are encoded as query params
     */
    suspend fun createAuthnResponse(authenticationRequestParameters: AuthenticationRequestParameters): String? {
        val params = createAuthnResponseParams(authenticationRequestParameters)
            ?: return null
        return AuthenticationResponse(
            url = authenticationRequestParameters.redirectUrl,
            params = params
        ).toUrl()
    }

    /**
     * Creates the authentication response from the RP's [params]
     */
    suspend fun createAuthnResponseParams(params: AuthenticationRequestParameters): AuthenticationResponseParameters? {
        val stateOfRelyingParty = params.state
            ?: return null
                .also { Napier.w("state is null") }
        val audience = params.clientMetadata?.jsonWebKeySet?.keys?.get(0)?.identifier
            ?: return null
                .also { Napier.w("Could not parse audience") }
        if (URN_TYPE_JWK_THUMBPRINT !in params.clientMetadata.subjectSyntaxTypesSupported)
            return null
                .also { Napier.w("Incompatible subject syntax types algorithms") }
        if (params.clientId != params.redirectUrl)
            return null
                .also { Napier.w("client_id does not match redirect_uri") }
        if (ID_TOKEN !in params.responseType)
            return null
                .also { Napier.w("response_type is not \"$ID_TOKEN\"") }
        // TODO "claims" may be set by the RP to tell OP which attributes to release
        if (VP_TOKEN !in params.responseType && params.presentationDefinition == null)
            return null
                .also { Napier.w("vp_token not requested") }
        if (params.clientMetadata.vpFormats == null)
            return null
                .also { Napier.w("Incompatible subject syntax types algorithms") }
        if (params.clientMetadata.vpFormats.jwtVp?.algorithms?.contains(JwsAlgorithm.ES256.text) != true)
            return null
                .also { Napier.w("Incompatible JWT algorithms") }
        if (params.nonce == null)
            return null
                .also { Napier.w("nonce is null") }
        val vp = holder?.createPresentation(params.nonce, audience)
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
            audience = params.redirectUrl,
            issuedAt = now,
            expiration = now + 60.seconds,
            nonce = params.nonce,
        )
        val jwsPayload = idToken.serialize().encodeToByteArray()
        val jwsHeader = JwsHeader(JwsAlgorithm.ES256)
        val signedIdToken = jwsService.createSignedJwsAddingParams(jwsHeader, jwsPayload)
            ?: return null
                .also { Napier.w("Could not sign id_token") }
        val presentationSubmission = PresentationSubmission(
            id = uuid4().toString(),
            definitionId = params.presentationDefinition?.id ?: uuid4().toString(),
            descriptorMap = params.presentationDefinition?.inputDescriptors?.map {
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
        return AuthenticationResponseParameters(
            idToken = signedIdToken,
            state = params.state,
            vpToken = vp.jws,
            presentationSubmission = presentationSubmission,
        )
    }


}
