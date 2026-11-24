package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.OpenIdConstants.VerifierInfo.REGISTRATION_CERT_FORMAT
import at.asitplus.openid.TransactionData
import at.asitplus.openid.VerifierInfo
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.RequestedPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import com.benasher44.uuid.uuid4
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/** What a request over the W3C Digital Credentials API asks for, see [DcApiRequestOptions]. */
sealed interface DcApiPresentationRequest {
    /**
     * A typed request, converted to what each offered exchange protocol needs: a DCQL query for OpenID4VP, see
     * [CredentialPresentationRequestBuilder.toDCQLRequest], and an ISO `DeviceRequest` for ISO/IEC 18013-7 Annex C, see
     * [RequestedPresentation.toDeviceRequest], with the purpose hints of its credential sets.
     */
    data class Typed(val presentation: RequestedPresentation) : DcApiPresentationRequest

    /**
     * A raw request: a DCQL query, sent over OpenID4VP and converted for ISO/IEC 18013-7 Annex C, see
     * [at.asitplus.openid.dcql.toIso180137AnnexCDeviceRequest], or an ISO `DeviceRequest`, offered over Annex C only.
     */
    data class Raw(val request: CredentialPresentationRequest) : DcApiPresentationRequest
}

/**
 * Options of a request over the W3C Digital Credentials API, which [DcApiVerifier.createAuthnRequest] offers over one
 * or more exchange protocols, building the request of each protocol from [presentationRequest] only if it is offered.
 */
data class DcApiRequestOptions(
    val presentationRequest: DcApiPresentationRequest,

    /** Identifies the request for the validation of its response, see [DcApiVerifier.validateAuthnResponse]. */
    override val state: String = uuid4().toString(),

    /**
     * The origins of the verifier, required by signed OpenID4VP requests (OpenID4VP 1.0, A.2), and binding the
     * `readerAuth` of an ISO/IEC 18013-7 Annex C request to its single entry.
     */
    val expectedOrigins: List<String>? = null,

    /**
     * The response mode of OpenID4VP requests, [ResponseMode.DcApiJwt] by default, as "The Verifier MUST use the
     * Response Mode `dc_api.jwt`" (HAIP 1.0, 5.2), or [ResponseMode.DcApi]. Annex C always encrypts the response.
     */
    val responseMode: ResponseMode = ResponseMode.DcApiJwt,

    /** Transactions for the End-User to authorize, sent over OpenID4VP only: offering Annex C with them fails. */
    val transactionData: List<TransactionData>? = null,

    /** Whether OpenID4VP requests embed the verifier metadata, see [VerifierMetadataMode]. */
    val verifierMetadataMode: VerifierMetadataMode = VerifierMetadataMode.AUTO,

    /**
     * The registration certificate (WRPRC) of the relying party, see [RelyingPartyRegistrationCertificate]; offering
     * an exchange protocol without its encoding fails.
     */
    val registrationCertificate: RelyingPartyRegistrationCertificate? = null,
) : RequestOptions {

    init {
        require(responseMode == ResponseMode.DcApi || responseMode == ResponseMode.DcApiJwt) {
            "responseMode must be ${ResponseMode.DcApi} or ${ResponseMode.DcApiJwt}, but is $responseMode"
        }
    }

    /** Requests [requestedPresentation], see [DcApiPresentationRequest.Typed], with the other parameters as above. */
    @JvmOverloads
    constructor(
        requestedPresentation: RequestedPresentation,
        state: String = uuid4().toString(),
        expectedOrigins: List<String>? = null,
        responseMode: ResponseMode = ResponseMode.DcApiJwt,
        transactionData: List<TransactionData>? = null,
        verifierMetadataMode: VerifierMetadataMode = VerifierMetadataMode.AUTO,
        registrationCertificate: RelyingPartyRegistrationCertificate? = null,
    ) : this(
        presentationRequest = DcApiPresentationRequest.Typed(requestedPresentation),
        state = state,
        expectedOrigins = expectedOrigins,
        responseMode = responseMode,
        transactionData = transactionData,
        verifierMetadataMode = verifierMetadataMode,
        registrationCertificate = registrationCertificate,
    )

    companion object {
        /**
         * The DC API options of [options], whose raw request they keep: fails unless its `responseMode` is
         * `dc_api` or `dc_api.jwt`, `responseUrl` is unset and `responseType` is `vp_token`, as the DC API supports
         * no other (OpenID4VP 1.0, A.2), and for a `verifierInfo` element of another format than `registration_cert`.
         *
         * The WRPRC moves into [registrationCertificate]: the deprecated `euWrprc` as its CWT, and a single
         * `registration_cert` element of `verifierInfo`, given as compact JWS or its base64url encoding, as its JWT.
         * `populateClientId` is dropped, as [DcApiVerifier] sets `client_id` in signed requests only (OpenID4VP 1.0,
         * A.3.1, A.3.2).
         */
        @JvmStatic
        fun from(options: OpenId4VpRequestOptions): DcApiRequestOptions {
            require(options.isAnyDcApi) {
                "responseMode must be ${ResponseMode.DcApi} or ${ResponseMode.DcApiJwt}, but is ${options.responseMode}"
            }
            require(options.responseUrl == null) {
                "DC API does not support setting responseUrl"
            }
            require(options.responseType == VP_TOKEN) {
                "DC API responseType must be $VP_TOKEN only"
            }
            val presentationRequest = requireNotNull(options.presentationRequest) {
                "The request requests nothing"
            }

            return DcApiRequestOptions(
                presentationRequest = DcApiPresentationRequest.Raw(presentationRequest),
                state = options.state,
                expectedOrigins = options.expectedOrigins,
                responseMode = options.responseMode,
                transactionData = options.transactionData,
                verifierMetadataMode = options.verifierMetadataMode,
                registrationCertificate = options.extractRegistrationCertificate(),
            )
        }

        private fun OpenId4VpRequestOptions.extractRegistrationCertificate(): RelyingPartyRegistrationCertificate? {
            @Suppress("DEPRECATION") val jwt = verifierInfo.orEmpty().extractJwtRegistrationCertificate()
            @Suppress("DEPRECATION") val cwt = euWrprc

            val registrationCertificate = if (registrationCertificate != null || jwt != null || cwt != null)
                RelyingPartyRegistrationCertificate(
                    jwt = registrationCertificate?.jwt ?: jwt,
                    cwt = registrationCertificate?.cwt ?: cwt,
                )
            else
                null
            return registrationCertificate
        }

        private fun List<VerifierInfo>.extractJwtRegistrationCertificate(): String? {
            val others = filterNot { it.isRegistrationCertificate() }
            require(others.isEmpty()) {
                "verifier_info other than a registration_cert is not supported: $others"
            }
            require(size <= 1) {
                "verifier_info has several registration_cert elements"
            }
            return this.singleOrNull()?.registrationCertificateJwt()
        }

        private fun VerifierInfo.isRegistrationCertificate() =
            format.equals(REGISTRATION_CERT_FORMAT, ignoreCase = true)

        /** The compact JWS of this `registration_cert`, given as such or as its base64url encoding. */
        private fun VerifierInfo.registrationCertificateJwt(): String {
            val data = requireNotNull((data as? VerifierInfo.Data.StringData)?.value) {
                "The data of a registration_cert is a string"
            }
            return if (data.contains('.')) data else data.decodeToByteArray(Base64UrlStrict).decodeToString()
        }
    }
}
