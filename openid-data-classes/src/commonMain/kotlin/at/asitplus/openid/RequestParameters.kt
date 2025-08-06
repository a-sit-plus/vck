package at.asitplus.openid

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonClassDiscriminator

/**
 * Uses open serialization in order to avoid type-discriminator in serialization
 */
@JsonClassDiscriminator("")
@Serializable(with = RequestParametersSerializer::class)
sealed class RequestParameters {
    abstract val responseType: String?
    abstract val nonce: String?
    abstract val clientId: String?
    abstract val redirectUrl: String?
    abstract val responseUrl: String?
    abstract val issuer: String?
    abstract val audience: String?
    abstract val state: String?
    abstract val transactionData: List<TransactionDataBase64Url>?

    /**
     * Reads the [OpenIdConstants.ClientIdScheme] of this request either directly from [clientIdScheme],
     * or by extracting the prefix from [clientId] (as specified in OpenID4VP draft 22 onwards).
     */
    open val clientIdSchemeExtracted: OpenIdConstants.ClientIdScheme?
        get() = clientId?.let { OpenIdConstants.ClientIdScheme.decodeFromClientId(it) }

    /**
     * Reads the [clientId] and removes the prefix of the [clientIdSchemeExtracted],
     * as specified in OpenID4VP draft 22 onwards.
     * OpenID4VP states that the *full* [clientId] must be used for presentations and anything else.
     */
    open val clientIdWithoutPrefix: String?
        get() = clientId?.let { clientId ->
            clientIdSchemeExtracted?.let { clientId.removePrefix("${it.stringRepresentation}:") }
        }

    /**
     * Reads the [redirectUrl], or the [clientIdWithoutPrefix] if [clientIdSchemeExtracted] is
     * [OpenIdConstants.ClientIdScheme.RedirectUri], as specified in OpenID4VP draft 22 onwards.
     */
    open val redirectUrlExtracted: String?
        get() = redirectUrl
            ?: (clientIdSchemeExtracted as? OpenIdConstants.ClientIdScheme.RedirectUri)?.let { clientIdWithoutPrefix }

}



