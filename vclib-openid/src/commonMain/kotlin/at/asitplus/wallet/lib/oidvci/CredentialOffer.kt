package at.asitplus.wallet.lib.oidvci

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.wallet.lib.oidc.jsonSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * OID4VCI: The Credential Issuer sends Credential Offer using an HTTP GET request or an HTTP redirect to the Wallet's
 * Credential Offer Endpoint defined in Section 11.1.The Credential Offer object, which is a JSON-encoded object with
 * the Credential Offer parameters, can be sent by value or by reference.
 */
@Serializable
data class CredentialOfferUrlParameters(
    /**
     * OID4VCI: Object with the Credential Offer parameters. This MUST NOT be present when the `credential_offer_uri`
     * parameter is present.
     */
    @SerialName("credential_offer")
    val credentialOffer: String,

    /**
     * OID4VCI: String that is a URL using the `https` scheme referencing a resource containing a JSON object with the
     * Credential Offer parameters. This MUST NOT be present when the `credential_offer` parameter is present.
     */
    @SerialName("credential_offer_uri")
    val credentialOfferUrl: String,
)

@Serializable
data class CredentialOffer(
    /**
     * OID4VCI: REQUIRED. The URL of the Credential Issuer, as defined in Section 11.2.1, from which the Wallet is
     * requested to obtain one or more Credentials. The Wallet uses it to obtain the Credential Issuer's Metadata
     * following the steps defined in Section 11.2.2.
     */
    @SerialName("credential_issuer")
    val credentialIssuer: String,

    /**
     * OID4VCI: REQUIRED. Array of unique strings that each identify one of the keys in the name/value pairs stored in
     * the `credential_configurations_supported` Credential Issuer metadata. The Wallet uses these string values to
     * obtain the respective object that contains information about the Credential being offered as defined in
     * Section 11.2.3. For example, these string values can be used to obtain `scope` values to be used in the
     * Authorization Request.
     */
    @SerialName("credential_configuration_ids")
    val configurationIds: Collection<String>,

    /**
     * OID4VCI: OPTIONAL. If `grants` is not present or is empty, the Wallet MUST determine the Grant Types the
     * Credential Issuer's Authorization Server supports using the respective metadata. When multiple grants are
     * present, it is at the Wallet's discretion which one to use.
     */
    @SerialName("grants")
    val grants: CredentialOfferGrants? = null,
) {
    fun serialize() = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialOffer> =
            runCatching { jsonSerializer.decodeFromString<CredentialOffer>(input) }.wrap()
    }
}

/**
 * OID4VCI: Object indicating to the Wallet the Grant Types the Credential Issuer's Authorization Server is prepared to
 * process for this Credential Offer. Every grant is represented by a name/value pair. The name is the Grant Type
 * identifier; the value is an object that contains parameters either determining the way the Wallet MUST use the
 * particular grant and/or parameters the Wallet MUST send with the respective request(s).
 */
@Serializable
data class CredentialOfferGrants(
    @SerialName("authorization_code")
    val authorizationCode: CredentialOfferGrantsAuthCode? = null,

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: CredentialOfferGrantsPreAuthCode? = null
)

@Serializable
data class CredentialOfferGrantsAuthCode(
    /**
     * OID4VCI: OPTIONAL. String value created by the Credential Issuer and opaque to the Wallet that is used to bind
     * the subsequent Authorization Request with the Credential Issuer to a context set up during previous steps. If the
     * Wallet decides to use the Authorization Code Flow and received a value for this parameter, it MUST include it in
     * the subsequent Authorization Request to the Credential Issuer as the `issuer_state` parameter value.
     */
    @SerialName("issuer_state")
    val issuerState: String? = null,

    /**
     * OID4VCI: OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant
     * type when `authorization_servers` parameter in the Credential Issuer metadata has multiple entries. It MUST NOT
     * be used otherwise. The value of this parameter MUST match with one of the values in the `authorization_servers`
     * array obtained from the Credential Issuer metadata.
     */
    @SerialName("authorization_server")
    val authorizationServer: String? = null,
)

@Serializable
data class CredentialOfferGrantsPreAuthCode(
    /**
     * OID4VCI: REQUIRED. The code representing the Credential Issuer's authorization for the Wallet to obtain
     * Credentials of a certain type. This code MUST be short lived and single use. If the Wallet decides to use the
     * Pre-Authorized Code Flow, this parameter value MUST be included in the subsequent Token Request with the
     * Pre-Authorized Code Flow.
     */
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String,

    /**
     * OID4VCI: OPTIONAL. Object specifying whether the Authorization Server expects presentation of a Transaction Code
     * by the End-User along with the Token Request in a Pre-Authorized Code Flow. If the Authorization Server does not
     * expect a Transaction Code, this object is absent; this is the default.
     */
    @SerialName("tx_code")
    val transactionCode: CredentialOfferGrantsPreAuthCodeTransactionCode? = null,

    /**
     * OID4VCI: OPTIONAL. The minimum amount of time in seconds that the Wallet SHOULD wait between polling requests to
     * the token endpoint. If no value is provided, Wallets MUST use 5 as the default.
     */
    @SerialName("interval")
    val waitIntervalSeconds: Int? = 5,

    /**
     * OID4VCI: OPTIONAL string that the Wallet can use to identify the Authorization Server to use with this grant
     * type when `authorization_servers` parameter in the Credential Issuer metadata has multiple entries.
     */
    @SerialName("authorization_server")
    val authorizationServer: String? = null
)

@Serializable
data class CredentialOfferGrantsPreAuthCodeTransactionCode(
    /**
     * OID4VCI: OPTIONAL. String specifying the input character set. Possible values are `numeric` (only digits) and
     * `text` (any characters). The default is `numeric`.
     */
    @SerialName("input_mode")
    val inputMode: String? = "numeric",

    /**
     * OID4VCI: OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet to render the
     * input screen and improve the user experience.
     */
    @SerialName("length")
    val length: Int? = null,

    /**
     * OID4VCI: OPTIONAL. String containing guidance for the Holder of the Wallet on how to obtain the Transaction
     * Code, e.g., describing over which communication channel it is delivered.
     */
    @SerialName("description")
    val description: String? = null,
)