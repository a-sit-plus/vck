package at.asitplus.wallet.lib.openid

import at.asitplus.data.NonEmptyList
import at.asitplus.data.validation.third_party.kotlin.collections.requireIsNotNullOrEmpty
import at.asitplus.openid.OpenIdConstants
import at.asitplus.openid.OpenIdConstants.ResponseMode
import at.asitplus.openid.OpenIdConstants.SCOPE_OPENID
import at.asitplus.openid.OpenIdConstants.SCOPE_PROFILE
import at.asitplus.openid.OpenIdConstants.VP_TOKEN
import at.asitplus.openid.TransactionData
import at.asitplus.openid.VerifierInfo
import at.asitplus.wallet.lib.RequestOptions
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialPresentationRequest.*
import com.benasher44.uuid.uuid4

enum class VerifierMetadataMode {
    AUTO,
    OMIT_IF_OUT_OF_BAND,
}

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
     * Note that support for requesting an `id_token` has been removed from this library.
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
     * OID4VP 1.0: OPTIONAL. A non-empty array of attestations about the Verifier relevant to the Credential Request.
     * These attestations MAY include Verifier metadata, policies, trust status, or authorizations.
     */
    val verifierInfo: NonEmptyList<VerifierInfo>? = null,

    /**
     * Whether the client_id should be added to the request. Required for DC API:
     * The client_id parameter MUST be omitted in unsigned requests defined in Appendix A.3.1.
     * The client_id parameter MUST be present in signed requests defined in Appendix A.3.2, as it communicates to the
     * Wallet which Client Identifier Prefix and Client Identifier to use when authenticating the client through
     * verification of the request signature or retrieving client metadata.
     */
    val populateClientId: Boolean = true,

    /**
     * Controls whether verifier metadata should be embedded in the authentication request.
     *
     * [VerifierMetadataMode.OMIT_IF_OUT_OF_BAND] may be used when the Wallet already knows the verifier metadata
     * through another mechanism, e.g., a profile-specific static configuration.
     */
    val verifierMetadataMode: VerifierMetadataMode = VerifierMetadataMode.AUTO,
) : RequestOptions {

    init {
        @Suppress("DEPRECATION")
        require(presentationRequest !is PresentationExchangeRequest) {
            "Presentation Exchange is not supported by OpenID4VP; use DCQL"
        }
        if (!transactionData.isNullOrEmpty()) {
            val transactionIds = transactionData.map { it.credentialIds.toList() }.flatten().toSet()
            @Suppress("DEPRECATION") val credentialIds = when (presentationRequest) {
                is DCQLRequest -> presentationRequest.dcqlQuery
                    .credentials.map { it.id.string }

                is PresentationExchangeRequest -> presentationRequest.presentationDefinition
                    .inputDescriptors.map { it.id }

                is IsoDeviceRetrieval -> setOf() // Transaction Data not supported for Device Retrieval
                null -> setOf()
            }.toSet()
            require(transactionIds == credentialIds) {
                "TransactionIds must match the credentialIds"
            }
        }
        if (isAnyDcApi) {
            require(isDcql || isDeviceRetrieval) { "DC API only supports DCQL or DeviceRetrieval" }
            if (populateClientId) {
                // should be a signed DC API request if client_id has to be assigned
                expectedOrigins.requireIsNotNullOrEmpty { "Expected origins must be set for DC API" }
            }
        } else {
            require(populateClientId) { "client_id should be set for anything but (unsigned) DC API requests" }
        }
        if (verifierMetadataMode == VerifierMetadataMode.OMIT_IF_OUT_OF_BAND) {
            require(!responseMode.requiresEncryption) {
                "verifier metadata cannot be omitted for encrypted response modes without any key distribution mechanism"
            }
        }
    }

    val isDcql: Boolean
        get() = presentationRequest is DCQLRequest

    val isDeviceRetrieval: Boolean
        get() = presentationRequest is IsoDeviceRetrieval

    val isAnyDirectPost: Boolean
        get() = (responseMode == ResponseMode.DirectPost) ||
                (responseMode == ResponseMode.DirectPostJwt)

    val isAnyDcApi: Boolean
        get() = responseMode == ResponseMode.DcApi || responseMode == ResponseMode.DcApiJwt

    @Deprecated("Support for SIOPv2 has been removed")
    val isSiop: Boolean
        get() = responseType.contains(OpenIdConstants.ID_TOKEN)

    @Deprecated("Support for SIOPv2 has been removed")
    fun buildScope(): String = listOf(SCOPE_OPENID, SCOPE_PROFILE).joinToString(" ")
}
