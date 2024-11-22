package at.asitplus.wallet.lib.jws


object JwsContentTypeConstants {
    const val JWT = "jwt"
    const val SD_JWT = "vc+sd-jwt"
    const val KB_JWT = "kb+jwt"
    const val OAUTH_AUTHZ_REQUEST = "oauth-authz-req+jwt"
    /** RFC 9449 */
    const val DPOP_JWT = "dpop+jwt"
    const val DIDCOMM_PLAIN_JSON = "didcomm-plain+json"
    const val DIDCOMM_SIGNED_JSON = "didcomm-signed+json"
    const val DIDCOMM_ENCRYPTED_JSON = "didcomm-encrypted+json"
}