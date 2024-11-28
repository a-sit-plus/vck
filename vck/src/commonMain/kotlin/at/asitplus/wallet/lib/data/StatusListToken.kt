package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import kotlinx.datetime.Instant

sealed interface StatusListToken {
    val resolvedAt: Instant?
    val payload: StatusListTokenPayload

    fun validate(
        statusListInfo: StatusListInfo,
        validateStatusListTokenIntegrity: (StatusListToken) -> StatusListTokenPayload,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<Unit> = at.asitplus.catching {
        StatusListTokenValidator.validateStatusListToken(
            statusListToken = this,
            statusListTokenResolvedAt = resolvedAt,
            validateStatusListTokenIntegrity = validateStatusListTokenIntegrity,
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast,
        ).getOrThrow()
    }

    fun extractTokenStatus(
        statusListInfo: StatusListInfo,
        zlibService: ZlibService? = null,
    ): KmmResult<TokenStatus> = at.asitplus.catching {
        StatusListTokenValidator.extractTokenStatus(
            statusList = payload.statusList,
            statusListInfo = statusListInfo,
            zlibService = zlibService,
        )
    }

    data class StatusListJwt(
        val value: JwsSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken {
        override val payload: StatusListTokenPayload
            get() = value.payload
    }

    data class StatusListCwt(
        val value: CoseSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken {
        override val payload: StatusListTokenPayload
            get() = value.payload ?: throw IllegalStateException("Payload not found.")
    }
}