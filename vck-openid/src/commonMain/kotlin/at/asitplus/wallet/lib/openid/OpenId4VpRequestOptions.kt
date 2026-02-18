package at.asitplus.wallet.lib.openid

import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.TransactionData
import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.RequestOptionsCredential
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import com.benasher44.uuid.uuid4

data class OpenId4VpRequestOptions(
    /**
     * Presentation mechanism to be used for requesting credentials.
     * Use [CredentialPresentationRequestBuilder] for simple requests.
     */
    val presentationRequest: CredentialPresentationRequest?,

    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode],
     * by default [OpenIdConstants.ResponseMode.Fragment].
     * Setting this to any other value may require setting [responseUrl] too.
     */
    val responseMode: ResponseMode = ResponseMode.Fragment,

    /**
     * Response URL to set in the [at.asitplus.openid.AuthenticationRequestParameters.responseUrl],
     * required if [responseMode] is set to [OpenIdConstants.ResponseMode.DirectPost] or
     * [OpenIdConstants.ResponseMode.DirectPostJwt].
     */
    val responseUrl: String? = null,

    /**
     * Response type to set in [at.asitplus.openid.AuthenticationRequestParameters.responseType],
     * by default only `vp_token` (as per OpenID4VP spec, see [OpenIdConstants.VP_TOKEN]).
     * Be sure to separate values by a space, e.g. `vp_token id_token` (see [OpenIdConstants.ID_TOKEN]).
     */
    val responseType: String = VP_TOKEN,

    /** Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]. */
    override val state: String = uuid4().toString(),

    /**
     * Non-empty array of strings, where each string is a base64url-encoded JSON object that contains a typed parameter
     * set with details about the transaction that the Verifier is requesting the End-User to authorize.
     */
    val transactionData: List<TransactionData>? = null,

    /**
     * REQUIRED when signed requests defined in Appendix A.3.2 are used with the
     * Digital Credentials API(DC API). A non-empty array of strings, each string representing an Origin of the Verifier
     * that is making the request. The Wallet MUST compare values in this parameter to the Origin to detect replay of
     * the request from a malicious Verifier. If the Origin does not match any of the entries in expected_origins,
     * the Wallet MUST return an error. This error SHOULD be an invalid_request error. This parameter is not for use in
     * unsigned requests and therefore a Wallet MUST ignore this parameter if it is present in an unsigned request.
     */
    val expectedOrigins: List<String>? = null,

    /**
     * Whether the client_id should be added to the request. Required for DC API:
     * The client_id parameter MUST be omitted in unsigned requests defined in Appendix A.3.1.
     * The client_id parameter MUST be present in signed requests defined in Appendix A.3.2, as it communicates to the
     * Wallet which Client Identifier Prefix and Client Identifier to use when authenticating the client through
     * verification of the request signature or retrieving client metadata.
     */
    val populateClientId: Boolean = true,
) : RequestOptions {
    @Deprecated("Replace with primary constructor, building a presentation request using [CredentialPresentationRequestBuilder]")
    constructor(
        credentials: Set<RequestOptionsCredential>,
        presentationMechanism: PresentationMechanismEnum = PresentationMechanismEnum.PresentationExchange,
        responseMode: ResponseMode = ResponseMode.Fragment,
        responseUrl: String? = null,
        responseType: String = VP_TOKEN,
        state: String = uuid4().toString(),
        transactionData: List<TransactionData>? = null,
        expectedOrigins: List<String>? = null,
        populateClientId: Boolean = true,
    ) : this(
        presentationRequest = CredentialPresentationRequestBuilder(
            credentials = credentials
        ).let {
            when(presentationMechanism) {
                PresentationMechanismEnum.PresentationExchange -> it.toPresentationExchangeRequest()
                PresentationMechanismEnum.DCQL -> it.toDCQLRequest()
                PresentationMechanismEnum.DeviceRequest -> throw IllegalArgumentException("Invalid presentation mechanism for OpenId4VP: $presentationMechanism")
            }
        },
        responseMode = responseMode,
        responseUrl = responseUrl,
        responseType = responseType,
        state = state,
        transactionData = transactionData,
        expectedOrigins = expectedOrigins,
        populateClientId = populateClientId,
    )

    init {
        if (!transactionData.isNullOrEmpty()) {
            val transactionIds = transactionData.map { it.credentialIds.toList() }.flatten().toSet()
            val credentialIds = when(presentationRequest) {
                is CredentialPresentationRequest.DCQLRequest -> presentationRequest.dcqlQuery.credentials.map {
                    it.id.string
                }
                is CredentialPresentationRequest.PresentationExchangeRequest -> presentationRequest.presentationDefinition.inputDescriptors.map {
                    it.id
                }

                null -> setOf()
            }.toSet()
            require(transactionIds == credentialIds) { "OpenId4VP defines that the credential_ids that must be part of a transaction_data element have to be an ID from InputDescriptor" }
        }
        if (isAnyDcApi) {
            require(isDcql) { "DC API only supports DCQL" }
            requireNotNull(expectedOrigins) { "Expected origins must be set for DC API" }
        } else {
            require(populateClientId) { "client_id should be set for anything but (unsigned) DC API requests" }
        }
    }

    val isDcql: Boolean
        get() = presentationRequest is CredentialPresentationRequest.DCQLRequest

    val isAnyDirectPost: Boolean
        get() = (responseMode == ResponseMode.DirectPost) ||
                (responseMode == ResponseMode.DirectPostJwt)

    val isAnyDcApi: Boolean
        get() = responseMode == ResponseMode.DcApi || responseMode == ResponseMode.DcApiJwt

    val isSiop: Boolean
        get() = responseType.contains(OpenIdConstants.ID_TOKEN)

    fun buildScope(): String = listOf(SCOPE_OPENID, SCOPE_PROFILE).joinToString(" ")
}

