package at.asitplus.wallet.lib.openid

import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.openid.OpenIdConstants
import at.asitplus.wallet.lib.data.ConstantIndex
import com.benasher44.uuid.uuid4

data class RequestOptions(
    /**
     * Requested credentials, should be at least one
     */
    val credentials: Set<RequestOptionsCredential>,
    /**
     * Response mode to request, see [OpenIdConstants.ResponseMode],
     * by default [OpenIdConstants.ResponseMode.Fragment].
     * Setting this to any other value may require setting [responseUrl] too.
     */
    val responseMode: OpenIdConstants.ResponseMode = OpenIdConstants.ResponseMode.Fragment,
    /**
     * Response URL to set in the [AuthenticationRequestParameters.responseUrl],
     * required if [responseMode] is set to [OpenIdConstants.ResponseMode.DirectPost] or
     * [OpenIdConstants.ResponseMode.DirectPostJwt].
     */
    val responseUrl: String? = null,
    /**
     * Response type to set in [AuthenticationRequestParameters.responseType],
     * by default only `vp_token` (as per OpenID4VP spec, see [OpenIdConstants.VP_TOKEN]).
     * Be sure to separate values by a space, e.g. `vp_token id_token` (see [OpenIdConstants.ID_TOKEN]).
     */
    val responseType: String = OpenIdConstants.VP_TOKEN,
    /**
     * Opaque value which will be returned by the OpenId Provider and also in [AuthnResponseResult]
     */
    val state: String = uuid4().toString(),
    /**
     * Optional URL to include metadata by reference (see [AuthenticationRequestParameters.clientMetadataUri])
     * instead of by value (see [AuthenticationRequestParameters.clientMetadata])
     */
    val clientMetadataUrl: String? = null,
    /**
     * Set this value to include metadata with encryption parameters set. Beware if setting this value and also
     * [clientMetadataUrl], that the URL shall point to [OpenId4VpVerifier.metadataWithEncryption].
     */
    val encryption: Boolean = false,
)

data class RequestOptionsCredential(
    /**
     * Credential type to request, or `null` to make no restrictions
     */
    val credentialScheme: ConstantIndex.CredentialScheme,
    /**
     * Required representation, see [ConstantIndex.CredentialRepresentation]
     */
    val representation: ConstantIndex.CredentialRepresentation = ConstantIndex.CredentialRepresentation.PLAIN_JWT,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * or `null` to make no restrictions
     */
    val requestedAttributes: Set<String>? = null,
    /**
     * List of attributes that shall be requested explicitly (selective disclosure),
     * but are not required (i.e. marked as optional),
     * or `null` to make no restrictions
     */
    val requestedOptionalAttributes: Set<String>? = null,
)
