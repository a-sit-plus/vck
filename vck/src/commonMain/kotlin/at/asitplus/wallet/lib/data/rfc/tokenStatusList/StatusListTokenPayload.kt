package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TimeToLive
import at.asitplus.wallet.lib.data.rfc7519.primitives.ExpirationTime
import at.asitplus.wallet.lib.data.rfc7519.primitives.NumericDate
import at.asitplus.wallet.lib.data.rfc7519.primitives.StringOrURI
import kotlinx.serialization.Serializable

@Serializable(with = StatusListTokenPayloadSerializer::class)
data class StatusListTokenPayload(
    val subject: StringOrURI,
    val issuedAt: NumericDate,
    val expirationTime: ExpirationTime? = null,
    val timeToLive: TimeToLive? = null,
    val statusList: StatusList,
)

