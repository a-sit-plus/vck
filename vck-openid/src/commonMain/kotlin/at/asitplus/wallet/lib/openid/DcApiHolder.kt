package at.asitplus.wallet.lib.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dcapi.DCAPIResponse
import at.asitplus.dcapi.DigitalCredentialInterface
import at.asitplus.dcapi.IsoMdocResponse
import at.asitplus.openid.RequestParametersFrom.*
import at.asitplus.wallet.lib.agent.CredentialMatchingResult
import at.asitplus.wallet.lib.agent.EphemeralKeyWithoutCert
import at.asitplus.wallet.lib.agent.Holder
import at.asitplus.wallet.lib.agent.HolderAgent
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.validation.RelyingPartyValidator
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.ValidationReport
import kotlin.jvm.JvmOverloads

/**
 * Handles requests received through the W3C Digital Credentials API, similar to [DcApiVerifier] on the relying
 * party side.
 *
 * The browser API may transport OpenID4VP or ISO/IEC 18013-7 Annex C requests. This class provides one wallet-facing
 * entry point and delegates the protocol-specific work to [OpenId4VpHolder] or [Iso180137AnnexCHolder].
 */
class DcApiHolder @JvmOverloads constructor(
    private val keyMaterial: KeyMaterial = EphemeralKeyWithoutCert(),
    private val holder: Holder = HolderAgent(keyMaterial),
    private val openId4VpHolder: OpenId4VpHolder = OpenId4VpHolder(holder = holder),
    private val iso180137AnnexCHolder: Iso180137AnnexCHolder = Iso180137AnnexCHolder(
        keyMaterial = keyMaterial,
        holder = holder,
    ),
    /**
     * Validates the relying party behind ISO/IEC 18013-7 Annex C requests that carry registration certificates, see
     * [RelyingPartyValidator]; configure the one for OpenID4VP requests on [openId4VpHolder].
     */
    private val relyingPartyValidator: RelyingPartyValidator = RelyingPartyValidator(),
) {

    /**
     * Validates the request and prepares credential selection. Clients can inspect the returned state, ask for user
     * consent, and resume with [finalizeAuthorizationResponse].
     */
    suspend fun startAuthorizationResponsePreparation(
        request: DcApiRequest,
    ): KmmResult<DcApiPreparationState> = catching {
        when (request) {
            is OpenId4VpDcApiSigned -> DcApiPreparationState.OpenId4Vp(
                openId4VpHolder.startAuthorizationResponsePreparation(request).getOrThrow()
            )

            is OpenId4VpDcApiMultiSigned -> DcApiPreparationState.OpenId4Vp(
                openId4VpHolder.startAuthorizationResponsePreparation(request).getOrThrow()
            )

            is OpenId4VpDcApiUnsigned -> DcApiPreparationState.OpenId4Vp(
                openId4VpHolder.startAuthorizationResponsePreparation(request).getOrThrow()
            )

            is IsoMdocDcApi -> DcApiPreparationState.Iso180137AnnexC(
                request = request,
                presentationRequest = iso180137AnnexCHolder.createPresentationRequest(request).getOrThrow(),
            )
        }
    }

    /**
     * Validates [request] under [policy] and prepares credential selection like the overload without a policy, also
     * for a rejected request: check the decision of [DcApiRequestValidation.validationReport] before presenting.
     * For an ISO/IEC 18013-7 Annex C request, which has no request object, the report is the one of its relying
     * party if it carries registration certificates, else `null`.
     */
    suspend fun startAuthorizationResponsePreparation(
        request: DcApiRequest,
        policy: ValidationPolicy,
    ): KmmResult<DcApiRequestValidation> = catching {
        when (request) {
            is OpenId4VpDcApiSigned -> openId4VpHolder.startAuthorizationResponsePreparation(request, policy)
                .getOrThrow().toDcApi()

            is OpenId4VpDcApiMultiSigned -> openId4VpHolder.startAuthorizationResponsePreparation(request, policy)
                .getOrThrow().toDcApi()

            is OpenId4VpDcApiUnsigned -> openId4VpHolder.startAuthorizationResponsePreparation(request, policy)
                .getOrThrow().toDcApi()

            is IsoMdocDcApi -> DcApiRequestValidation(
                validationReport = request.takeIf { it.carriesRegistrationCertificate() }
                    ?.validateRelyingParty(relyingPartyValidator, policy)?.report,
                preparationState = DcApiPreparationState.Iso180137AnnexC(
                    request = request,
                    presentationRequest = iso180137AnnexCHolder.createPresentationRequest(request).getOrThrow(),
                ),
            )
        }
    }

    private fun IsoMdocDcApi.carriesRegistrationCertificate() =
        parameters.isoMdocRequest.deviceRequest.docRequests.any { it.itemsRequest.value.requestInfo?.euWrprc != null }

    private fun AuthorizationRequestValidation.toDcApi() =
        DcApiRequestValidation(validationReport, DcApiPreparationState.OpenId4Vp(preparationState))

    /** Matches wallet credentials using the protocol and platform-selected credential IDs recorded in [state]. */
    suspend fun getMatchingCredentials(
        state: DcApiPreparationState,
    ): KmmResult<CredentialMatchingResult<SubjectCredentialStore.StoreEntry>> =
        when (state) {
            is DcApiPreparationState.OpenId4Vp -> openId4VpHolder.getMatchingCredentials(state.state)
            is DcApiPreparationState.Iso180137AnnexC -> iso180137AnnexCHolder.getMatchingCredentials(state.request)
        }

    /**
     * Creates a protocol-agnostic response to return through the browser's Digital Credentials API.
     *
     * Encode the result with `toAndroidDcApiResponseJson()` on Android or, for an Annex C request,
     * `toIosIsoMdocResponseBytes()` on iOS. Annex C requires a
     * [CredentialPresentation.IsoDeviceRetrievalPresentation]; OpenID4VP uses the presentation type requested by
     * its [CredentialPresentationRequest].
     */
    suspend fun finalizeAuthorizationResponse(
        state: DcApiPreparationState,
        credentialPresentation: CredentialPresentation? = null,
    ): KmmResult<DigitalCredentialInterface> = catching {
        when (state) {
            is DcApiPreparationState.OpenId4Vp -> {
                val result = openId4VpHolder.finalizeAuthorizationResponse(
                    preparationState = state.state,
                    credentialPresentation = credentialPresentation,
                ).getOrThrow()
                require(result is AuthenticationResponseResult.DcApi) {
                    "Expected OpenID4VP DC API response"
                }
                require(result.params is DigitalCredentialInterface) {
                    "OpenID4VP DC API response is not a DigitalCredentialInterface"
                }
                result.params
            }

            is DcApiPreparationState.Iso180137AnnexC -> {
                require(credentialPresentation is CredentialPresentation.IsoDeviceRetrievalPresentation) {
                    "ISO 18013-7 Annex C requires an ISO Device Retrieval presentation"
                }
                IsoMdocResponse(
                    DCAPIResponse(
                        iso180137AnnexCHolder.finalizeResponse(
                            request = state.request,
                            credentialPresentation = credentialPresentation,
                        ).getOrThrow()
                    )
                )
            }
        }
    }
}

/**
 * Opaque continuation state for a two-step [DcApiHolder] flow.
 *
 * [presentationRequest] is suitable for UI rendering and credential selection. Pass the same state back to
 * [DcApiHolder.getMatchingCredentials] and [DcApiHolder.finalizeAuthorizationResponse].
 */
sealed class DcApiPreparationState {
    abstract val request: DcApiRequest
    abstract val presentationRequest: CredentialPresentationRequest?

    data class OpenId4Vp(
        val state: AuthorizationResponsePreparationState,
    ) : DcApiPreparationState() {
        override val request: DcApiRequest
            get() = state.request as DcApiRequest
        override val presentationRequest: CredentialPresentationRequest?
            get() = state.credentialPresentationRequest
    }

    data class Iso180137AnnexC(
        override val request: IsoMdocDcApi,
        override val presentationRequest: CredentialPresentationRequest.IsoDeviceRetrieval,
    ) : DcApiPreparationState()
}

/**
 * The [validationReport] of a request through the Digital Credentials API, and the [preparationState] to answer it
 * with, also if the request is rejected, see [DcApiHolder.startAuthorizationResponsePreparation].
 */
data class DcApiRequestValidation(
    /** `null` only for an ISO/IEC 18013-7 Annex C request without registration certificates. */
    val validationReport: ValidationReport?,
    val preparationState: DcApiPreparationState,
)
