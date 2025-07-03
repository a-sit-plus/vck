package at.asitplus.openid

import at.asitplus.KmmResult
import at.asitplus.catching
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

/**
 * OID4VCI: The Credential Issuer sends Credential Offer using an HTTP GET request or an HTTP redirect to the Wallet's
 * Credential Offer Endpoint defined in Section 11.1.The Credential Offer object, which is a JSON-encoded object with
 * the Credential Offer parameters, can be sent by value or by reference.
 */
@Serializable
data class CredentialOfferUrlParameters(
    /**
     * OID4VCI: Object with the Credential Offer parameters. This MUST NOT be present when the [credentialOfferUrl]
     * parameter is present.
     */
    @SerialName("credential_offer")
    val credentialOffer: JsonObject? = null,

    /**
     * OID4VCI: String that is a URL using the `https` scheme referencing a resource containing a JSON object with the
     * Credential Offer parameters. This MUST NOT be present when the [credentialOffer] parameter is present.
     */
    @SerialName("credential_offer_uri")
    val credentialOfferUrl: String? = null,
) {
    fun serialize() = odcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String): KmmResult<CredentialOfferUrlParameters> =
            catching { odcJsonSerializer.decodeFromString<CredentialOfferUrlParameters>(input) }
    }
}