package at.asitplus.wallet.lib.openid

/**
 * Options for creating requests for the W3C Digital Credentials API in [DcApiVerifier.createAuthnRequest],
 * reflecting the exchange protocols available over that API,
 * see [at.asitplus.dcapi.request.ExchangeProtocolIdentifier].
 */
sealed class DcApiCreationOptions {

    /**
     * Unsigned OpenID4VP 1.0 request, i.e. protocol `openid4vp-v1-unsigned`,
     * see [at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.OpenId4VpUnsigned].
     */
    data object OpenId4VpUnsigned : DcApiCreationOptions()

    /**
     * Signed OpenID4VP 1.0 request, i.e. protocol `openid4vp-v1-signed`,
     * see [at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.OpenId4VpSigned].
     */
    data object OpenId4VpSigned : DcApiCreationOptions()

    /** Compact signed OpenID4VP request using the supplied verifier identity. */
    data class OpenId4VpSignedBy(val signer: DcApiRequestSigner) : DcApiCreationOptions()

    /** JWS General JSON OpenID4VP request protected by at least two verifier identities. */
    data class OpenId4VpMultiSigned(val signers: List<DcApiRequestSigner>) : DcApiCreationOptions() {
        init {
            require(signers.size >= 2) { "A multisigned request requires at least two signers" }
            require(signers.map { it.clientIdScheme.clientId }.distinct().size == signers.size) {
                "A multisigned request requires distinct client identifiers"
            }
        }
    }

    /**
     * ISO 18013-7 Annex C request, i.e. protocol `org-iso-mdoc`,
     * see [at.asitplus.dcapi.request.verifier.DigitalCredentialGetRequest.IsoMdoc].
     */
    data object Iso180137AnnexC : DcApiCreationOptions()
}
