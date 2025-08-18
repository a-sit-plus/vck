package at.asitplus.requests

import at.asitplus.dif.PresentationDefinition
import at.asitplus.openid.AuthnRequestClaims
import at.asitplus.openid.RelyingPartyMetadata
import at.asitplus.openid.TransactionDataBase64Url
import kotlinx.serialization.SerialName

interface OidcAuthRequest : AuthenticationRequest{
    /**
     * OpenID4VP: When received in [at.asitplus.openid.RequestObjectParameters.walletNonce], the Verifier MUST use it as the [walletNonce]
     * value in the signed authorization request object.
     * Value can be a base64url-encoded, fresh, cryptographically random number with sufficient entropy.
     */
    @SerialName("wallet_nonce")
    val walletNonce: String?

    /**
     * OIDC: OPTIONAL. This parameter is used to request that specific Claims be returned. The value is a JSON object
     * listing the requested Claims.
     */
    @SerialName("claims")
    val claims: AuthnRequestClaims?

    /**
     * OIDC SIOPv2: OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP
     * that would normally be provided to an OP during Dynamic RP Registration.
     * It MUST not be present if the RP uses OpenID Federation 1.0 Automatic Registration to pass its metadata.
     */
    @SerialName("client_metadata")
    val clientMetadata: RelyingPartyMetadata?

    /**
     * OIDC SIOPv2: OPTIONAL. This parameter is used by the RP to provide information about itself to a Self-Issued OP
     * that would normally be provided to an OP during Dynamic RP Registration.
     * It MUST not be present if the RP uses OpenID Federation 1.0 Automatic Registration to pass its metadata.
     */
    @SerialName("client_metadata_uri")
    val clientMetadataUri: String?

    /**
     * OIDC: OPTIONAL. ID Token previously issued by the Authorization Server being passed as a hint about the
     * End-User's current or past authenticated session with the Client. If the End-User identified by the ID Token is
     * logged in or is logged in by the request, then the Authorization Server returns a positive response; otherwise,
     * it SHOULD return an error, such as login_required.
     */
    @SerialName("id_token_hint")
    val idTokenHint: String?

    /**
     * OpenID4VP: OPTIONAL. A string determining the HTTP method to be used when the [requestUri] parameter is included
     * in the same request. Two case-sensitive valid values are defined in this specification: `get` and `post`.
     * If [requestUriMethod] value is `get`, the Wallet MUST send the request to retrieve the Request Object using the
     * HTTP GET method, i.e., as defined in RFC9101. If [requestUriMethod] value is `post`, a supporting Wallet MUST
     * send the request using the HTTP POST method as detailed in Section 5.11. If the [requestUriMethod] parameter is
     * not present, the Wallet MUST process the [requestUri] parameter as defined in RFC9101. Wallets not supporting
     * the post method will send a GET request to the Request URI (default behavior as defined in RFC9101).
     * [requestUriMethod] parameter MUST NOT be present if a [requestUri] parameter is not present.
     */
    @SerialName("request_uri_method")
    val requestUriMethod: String?

    /**
     * OIDC SIOPv2: OPTIONAL. Space-separated string that specifies the types of ID Token the RP wants to obtain, with
     * the values appearing in order of preference. The allowed individual values are `subject_signed_id_token` and
     * `attester_signed_id_token`. The default value is `attester_signed_id_token`. The RP determines the type if
     * ID Token returned based on the comparison of the `iss` and `sub` claims values. In order to preserve
     * compatibility with existing OpenID Connect deployments, the OP MAY return an ID Token that does not fulfill the
     * requirements as expressed in this parameter. So the RP SHOULD be prepared to reliably handle such an outcome.
     *
     * See [at.asitplus.openid.IdTokenType] for valid values.
     */
    @SerialName("id_token_type")
    val idTokenType: String?

    /**
     * OID4VP: A string containing a Presentation Definition JSON object. This parameter MUST be present when
     * [presentationDefinitionUrl] parameter, or a [scope] value representing a Presentation Definition is not
     * present.
     */
    @SerialName("presentation_definition")
    val presentationDefinition: PresentationDefinition?

    /**
     * OID4VP: OPTIONAL. Array of strings, where each string is a base64url encoded JSON object that contains a typed
     * parameter set with details about the transaction that the Verifier is requesting the End-User to authorize.
     * The Wallet MUST return an error if a request contains even one unrecognized transaction data type or transaction
     * data not conforming to the respective type definition.
     *
     * Transaction data classes are implemented in module [rqes-data-classes] and thus not known at compile time.
     * For the contextual serializer see [at.asitplus.rqes.serializers.Base64URLTransactionDataSerializer]
     */
    @SerialName("transaction_data")
    val transactionData: List<TransactionDataBase64Url>?

}