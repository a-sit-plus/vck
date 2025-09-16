package at.asitplus.wallet.lib.jws


object JwsContentTypeConstants {
    const val JWT = "jwt"
    /** SD-JWT: `dc+sd-jwt` */
    const val SD_JWT = "dc+sd-jwt"
    /** Key binding JWT for SD-JWT: `kb+jwt` */
    const val KB_JWT = "kb+jwt"
    /** Access tokens for OID4VCI: `oid4vci+at+jwt` */
    const val OID4VCI_AT_JWT = "oid4vci+at+jwt"
    /** Refresh tokens: `rt+jwt+ */
    const val RT_JWT = "rt+jwt"
    const val OAUTH_AUTHZ_REQUEST = "oauth-authz-req+jwt"
    /** RFC 9449: DPoP: `dpop+jwt` */
    const val DPOP_JWT = "dpop+jwt"
    /** OAuth 2.0 Attestation-Based Client Authentication */
    const val CLIENT_ATTESTATION_JWT = "oauth-client-attestation+jwt"
    /** OAuth 2.0 Attestation-Based Client Authentication */
    const val CLIENT_ATTESTATION_POP_JWT = "oauth-client-attestation-pop+jwt"
}