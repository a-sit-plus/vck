package at.asitplus.openid

interface RequestParameters {
    val responseType: String?
    val nonce: String?
    val clientId: String?
    val redirectUrl: String?
    val responseUrl: String?
    val issuer: String?
    val audience: String?
    val state: String?
    val transactionData: Set<String>?

    /**
     * Reads the [OpenIdConstants.ClientIdScheme] of this request either directly from [clientIdScheme],
     * or by extracting the prefix from [clientId] (as specified in OpenID4VP draft 22 onwards).
     */
    val clientIdSchemeExtracted: OpenIdConstants.ClientIdScheme?
        get() = clientId?.let { OpenIdConstants.ClientIdScheme.decodeFromClientId(it) }

    /**
     * Reads the [clientId] and removes the prefix of the [clientIdSchemeExtracted],
     * as specified in OpenID4VP draft 22 onwards.
     * OpenID4VP states that the *full* [clientId] must be used for presentations and anything else.
     */
    val clientIdWithoutPrefix: String?
        get() = clientId?.let { clientId ->
            clientIdSchemeExtracted?.let { clientId.removePrefix("${it.stringRepresentation}:") }
        }

    /**
     * Reads the [redirectUrl], or the [clientIdWithoutPrefix] if [clientIdSchemeExtracted] is
     * [OpenIdConstants.ClientIdScheme.RedirectUri], as specified in OpenID4VP draft 22 onwards.
     */
    val redirectUrlExtracted: String?
        get() = redirectUrl
            ?: (clientIdSchemeExtracted as? OpenIdConstants.ClientIdScheme.RedirectUri)?.let { clientIdWithoutPrefix }

}



