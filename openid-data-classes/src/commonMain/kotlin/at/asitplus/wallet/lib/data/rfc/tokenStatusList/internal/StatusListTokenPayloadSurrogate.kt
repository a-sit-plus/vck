package at.asitplus.wallet.lib.data.rfc.tokenStatusList.internal

import at.asitplus.signum.indispensable.josef.io.InstantLongSerializer
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDuration
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.PositiveDurationSecondsULongSerializer
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * Helper class
 */
@Serializable
internal data class StatusListTokenPayloadSurrogate(
    @SerialName("sub")
    val subject: UniformResourceIdentifier,
    @SerialName("iat")
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant,
    @SerialName("exp")
    @Serializable(with = InstantLongSerializer::class)
    val expirationTime: Instant? = null,
    @SerialName("ttl")
    @Serializable(with = PositiveDurationSecondsULongSerializer::class)
    val timeToLive: PositiveDuration? = null,
    @SerialName("status_list")
    val statusList: StatusList? = null,
    @SerialName("identifier_list")
    val identifierList: IdentifierList? = null,
)