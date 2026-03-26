package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload.StatusListTokenPayloadSurrogateSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.cbor.CborConfiguration
import kotlin.time.Instant

/**
 * Common model for status list tokens serialized either as JWT claims or as CWT claims.
 *
 * Serialization differs by format:
 * - JWT uses the textual claim names `sub`, `iat`, `exp`, `ttl`, and `status_list`
 * - CWT uses the corresponding numeric labels `2`, `6`, `4`, `65534`, and `65533`
 * - `ttl` is encoded as a JSON number for JWT and as a CBOR unsigned integer for CWT
 * - `identifier_list` is only supported for CWT/CBOR and uses label `65530`
 *
 * For correct CWT serialization [Cbor] must use [CborConfiguration.preferCborLabelsOverNames].
 * This is the default for [Cbor.CoseCompliant] serializers such as [coseCompliantSerializer].
 */
@Serializable(with = StatusListTokenPayloadSurrogateSerializer::class)
data class StatusListTokenPayload(
    /**
     * REQUIRED. The subject claim identifying the URI of the status list token.
     *
     * JWT serializes this as claim `sub`.
     * CWT serializes this as label `2`.
     */
    val subject: UniformResourceIdentifier,

    /**
     * REQUIRED. The issued-at timestamp of the status list token.
     *
     * JWT serializes this as claim `iat`.
     * CWT serializes this as label `6`.
     */
    val issuedAt: Instant,

    /**
     * RECOMMENDED. The expiration timestamp of the status list token.
     *
     * JWT serializes this as claim `exp`.
     * CWT serializes this as label `4`.
     */
    val expirationTime: Instant? = null,
    /**
     * OPTIONAL. Maximum cache lifetime of the token.
     *
     * JWT serializes this as claim `ttl` encoded as a JSON number of seconds.
     * CWT serializes this as label `65534` encoded as a CBOR unsigned integer of seconds.
     */
    val timeToLive: PositiveDuration? = null,

    /**
     * REQUIRED. The revocation data carried by the token.
     *
     * - [StatusList] is supported in both formats and is serialized as `status_list` in JWT
     *   and label `65533` in CWT.
     * - [IdentifierList] is only supported in CWT/CBOR and is serialized as `identifier_list`
     *   with label `65530`.
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
