package at.asitplus.wallet.lib.jws


object JwsContentTypeConstants {
    const val JWT = "jwt"
    // TODO In 5.4.0, use "dc+sd-jwt" instead of "vc+sd-jwt"
    const val SD_JWT = "vc+sd-jwt"
    /** Key binding JWT for SD-JWT: `kb+jwt` */
    const val KB_JWT = "kb+jwt"
    /** Access tokens: `at+jwt` */
    const val AT_JWT = "at+jwt"
    const val OAUTH_AUTHZ_REQUEST = "oauth-authz-req+jwt"
    /** RFC 9449: DPoP: `dpop+jwt` */
    const val DPOP_JWT = "dpop+jwt"
    /** OAuth 2.0 Attestation-Based Client Authentication */
    const val CLIENT_ATTESTATION_JWT = "oauth-client-attestation+jwt"
    /** OAuth 2.0 Attestation-Based Client Authentication */
    const val CLIENT_ATTESTATION_POP_JWT = "oauth-client-attestation-pop+jwt"
    const val DIDCOMM_PLAIN_JSON = "didcomm-plain+json"
    const val DIDCOMM_SIGNED_JSON = "didcomm-signed+json"
    const val DIDCOMM_ENCRYPTED_JSON = "didcomm-encrypted+json"
}