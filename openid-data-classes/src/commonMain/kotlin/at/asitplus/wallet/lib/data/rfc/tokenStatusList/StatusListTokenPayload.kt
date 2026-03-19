package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload.StatusListTokenPayloadSurrogateSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlin.time.Instant

@Serializable(with = StatusListTokenPayloadSurrogateSerializer::class)
data class StatusListTokenPayload(
    /**
     * REQUIRED. As generally defined in RFC7519. The sub (subject) claim MUST specify the URI
     * of the Status List Token. The value MUST be equal to that of the uri claim contained in the
     * status_list claim of the Referenced Token.
     */
    val subject: UniformResourceIdentifier,

    /**
     * REQUIRED. As generally defined in RFC7519. The iat (issued at) claim MUST specify the
     * time at which the Status List Token was issued.
     */
    val issuedAt: Instant,

    /**
     * RECOMMENDED. As generally defined in RFC7519. The exp (expiration time) claim, if present,
     * MUST specify the time at which the Status List Token is considered expired by the Status Issuer.
     */
    val expirationTime: Instant? = null,
    /**
     * OPTIONAL. The time to live claim, if
     * present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be
     * cached by a consumer before a fresh copy SHOULD be retrieved. The value of the claim MUST be a
     * positive number.
     */
    val timeToLive: PositiveDuration? = null,

    /**
     * REQUIRED. Must specify a valid [RevocationList] either
     *  [StatusList] conforming to https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-05.html#name-status-list
     * or
     *  [IdentifierList] conforming to ISO18013-5 Ch 12.3.6
     */
    val revocationList: RevocationList,
) {
    internal object StatusListTokenPayloadSurrogateSerializer :
        TransformingSerializerTemplate<StatusListTokenPayload, StatusListTokenPayloadSurrogate>(
            parent = StatusListTokenPayloadSurrogate.Companion.serializer(),
            encodeAs = {
                StatusListTokenPayloadSurrogate(it)
            },
            decodeAs = {
                it.toStatusListTokenPayload()
            },
        )
}