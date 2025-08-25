package at.asitplus.openid

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * OpenID4VP: This request is (optionally) sent from the wallet when requesting the Request Object from the Verifier.
 *
 * Usually, these parameters are sent to the Request Endpoint URL of the OpenID Verifier.
 */
@Serializable
data class RequestObjectParameters(
    /**
     * OpenID4VP: OPTIONAL. A String containing a JSON object containing metadata parameters as defined in Section 9.
     *
     * See [walletMetadata] and its type [OAuth2AuthorizationServerMetadata].
     */
    @SerialName("wallet_metadata")
    val walletMetadataString: String? = null,

    /**
     * OpenID4VP: OPTIONAL. A String value used to mitigate replay attacks of the Authorization Request. When received,
     * the Verifier MUST use it as the `wallet_nonce` value in the signed authorization request object.
     * Value can be a base64url-encoded, fresh, cryptographically random number with sufficient entropy.
     */
    @SerialName("wallet_nonce")
    val walletNonce: String? = null,
) : RequestParameters() {

    constructor(metadata: OAuth2AuthorizationServerMetadata, nonce: String) : this(
        walletMetadataString = metadata.catchingUnwrapped { joseCompliantSerializer.encodeToString(this) }.getOrNull(),
        walletNonce = nonce
    )
    
    val walletMetadata: OAuth2AuthorizationServerMetadata?
        get() = walletMetadataString?.let {
            catchingUnwrapped {
                joseCompliantSerializer.decodeFromString<OAuth2AuthorizationServerMetadata>(it)
            }.getOrNull()
        }
}
