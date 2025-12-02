package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * The following content applies to the JWT Claims Set:
 *
 * sub: REQUIRED. As generally defined in RFC7519. The sub (subject) claim MUST specify the URI
 * of the Status List Token. The value MUST be equal to that of the uri claim contained in the
 * status_list claim of the Referenced Token.
 *
 * iat: REQUIRED. As generally defined in RFC7519. The iat (issued at) claim MUST specify the
 * time at which the Status List Token was issued.
 *
 * exp: OPTIONAL. As generally defined in RFC7519. The exp (expiration time) claim, if present,
 * MUST specify the time at which the Status List Token is considered expired by the Status Issuer.
 *
 * ttl: OPTIONAL. The ttl (time to live) claim, if present, MUST specify the maximum amount of
 * time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy
 * SHOULD be retrieved. The value of the claim MUST be a positive number encoded in JSON as a
 * number.
 *
 * ------
 * revocationList: Helper class; See [RevocationList]
 *
 */
@Serializable(with = StatusListTokenPayloadSerializer::class)
data class StatusListTokenPayload(
    val subject: UniformResourceIdentifier,
    val issuedAt: Instant,
    val expirationTime: Instant? = null,
    val timeToLive: PositiveDuration? = null,
    val revocationList: RevocationList,
)