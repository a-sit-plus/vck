package at.asitplus.wallet.lib.data.rfc.tokenStatusList.cwt

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc8392.primitives.NumericDate
import at.asitplus.wallet.lib.data.rfc8392.primitives.StringOrURI

/**
 * 2 (subject): REQUIRED. As generally defined in [RFC8392]. The subject claim MUST specify the URI of the Status List Token. The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token.
 *
 * 6 (issued at): REQUIRED. As generally defined in [RFC8392]. The issued at claim MUST specify the time at which the Status List Token was issued.
 *
 * 4 (expiration time): OPTIONAL. As generally defined in [RFC8392]. The expiration time claim, if present, MUST specify the time at which the Status List Token is considered expired by its issuer.
 *
 * 65534 (time to live): OPTIONAL. Unsigned integer (Major Type 0). The time to live claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a positive number.
 *
 * 65533 (status list): REQUIRED. The status list claim MUST specify the Status List conforming to the rules outlined in Section 4.2.
 */
@ExperimentalUnsignedTypes
interface CwtStatusListTokenPayloadClaimsProvider :
    OptionalCwtStatusListTokenPayloadClaimsProvider {
    override val status_list: StatusList
    override val sub: StringOrURI
    override val iat: NumericDate

    override val containsStatusListTokenPayload: Boolean
        get() = true
}