package at.asitplus.wallet.lib.data.rfc.tokenStatusList.jwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI

/**
 * The following content applies to the JWT Claims Set:
 *
 * sub: REQUIRED. As generally defined in [RFC7519]. The sub (subject) claim MUST specify the URI of the Status List Token. The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token.
 *
 * iat: REQUIRED. As generally defined in [RFC7519]. The iat (issued at) claim MUST specify the time at which the Status List Token was issued.
 *
 * exp: OPTIONAL. As generally defined in [RFC7519]. The exp (expiration time) claim, if present, MUST specify the time at which the Status List Token is considered expired by the Status Issuer.
 *
 * ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a positive number encoded in JSON as a number.
 *
 * status_list: REQUIRED. The status_list (status list) claim MUST specify the Status List conforming to the rules outlined in Section 4.1.
 */

interface JwtStatusListTokenPayloadClaimsProvider :
    OptionalJwtStatusListTokenPayloadClaimsProvider {
    override val sub: StringOrURI
    override val iat: NumericDate
    override val status_list: StatusList

    override val containsStatusListTokenPayload: Boolean
        get() = true

    override fun toStatusListTokenPayload() = StatusListTokenPayload(
        subject = sub,
        issuedAt = iat,
        expirationTime = exp,
        timeToLive = ttl,
        statusList = status_list,
    )
}


