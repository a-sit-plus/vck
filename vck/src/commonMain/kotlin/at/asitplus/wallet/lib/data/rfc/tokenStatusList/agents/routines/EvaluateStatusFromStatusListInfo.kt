package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.routines

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.datetime.Instant

fun interface EvaluateStatusFromStatusListInfo {
    suspend operator fun invoke(statusListInfo: StatusListInfo): KmmResult<TokenStatus>


    class WithValidationRules<StatusListToken : Any>(
        /**
         * In the successful response, the Status Provider MUST use the following content-type:
         *
         * "application/statuslist+jwt" for Status List Token in JWT format
         * "application/statuslist+cwt" for Status List Token in CWT format
         *
         * In the case of "application/statuslist+jwt", the response MUST be of type JWT and follow
         * the rules of Section 5.1. In the case of "application/statuslist+cwt", the response MUST
         * be of type CWT and follow the rules of Section 5.2.
         */
        val resolveStatusListToken: suspend (UniformResourceIdentifier) -> StatusListToken,
        /**
         * Validate the Status List Token:
         *
         * Validate the Status List Token by following the rules defined in section 7.2 of [RFC7519]
         * for JWTs and section 7.2 of [RFC8392] for CWTs
         */
        val validateStatusListTokenIntegrity: (StatusListToken) -> StatusListTokenPayload,
        val extractStatusListTokenResolvedAt: ((StatusListToken) -> Instant)? = null,

        val isInstantInThePast: (Instant) -> Boolean,
        val zlibService: ZlibService,
    ) : EvaluateStatusFromStatusListInfo {
        override suspend operator fun invoke(
            statusListInfo: StatusListInfo,
        ): KmmResult<TokenStatus> = catching {
            val statusListToken = resolveStatusListToken(statusListInfo.uri)

            val payload = StatusListTokenValidator.validateStatusListToken(
                statusListToken = statusListToken,
                statusListInfo = statusListInfo,
                validateStatusListTokenIntegrity = validateStatusListTokenIntegrity,
                isInstantInThePast = isInstantInThePast,
                statusListTokenResolvedAt = extractStatusListTokenResolvedAt?.invoke(statusListToken)
            ).getOrThrow()

            StatusListTokenValidator.extractTokenStatus(
                statusList = payload.statusList,
                statusListInfo = statusListInfo,
                zlibService = zlibService,
            )
        }
    }
}

