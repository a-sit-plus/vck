package at.asitplus.wallet.lib.data.rfc.tokenStatusList.agents.routines

import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusList
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import io.github.aakira.napier.Napier
import kotlinx.datetime.Instant

fun interface EvaluateStatusFromStatusListInfo {
    suspend operator fun invoke(statusListInfo: StatusListInfo): TokenStatus

    @ExperimentalUnsignedTypes
    class WithValidationRules<StatusListToken : Any>(
        val resolveStatusListToken: suspend (UniformResourceIdentifier) -> StatusListToken,
        /**
         * Validate the Status List Token:
         *
         * Validate the Status List Token by following the rules defined in section 7.2 of [RFC7519]
         * for JWTs and section 7.2 of [RFC8392] for CWTs
         *
         * Check for the existence of the required claims as defined in Section 5.1 and Section 5.2
         * depending on token type.
         */
        val validateStatusListToken: (StatusListToken) -> StatusListTokenPayload,
        val extractStatusListTokenResolvedAt: ((StatusListToken) -> Instant)? = null,

        val isInstantInThePast: (Instant) -> Boolean,
    ) : EvaluateStatusFromStatusListInfo {
        override suspend operator fun invoke(
            statusListInfo: StatusListInfo,
        ): TokenStatus {
            /**
             * Resolve the Status List Token from the provided URI.
             */
            val statusListToken = resolveStatusListToken(statusListInfo.uri)

            /**
             * Validate the Status List Token:
             *
             * Validate the Status List Token by following the rules defined in section 7.2 of [RFC7519]
             * for JWTs and section 7.2 of [RFC8392] for CWTs
             *
             * Check for the existence of the required claims as defined in Section 5.1 and Section 5.2
             * depending on token type.
             */
            val payload = validateStatusListToken(statusListToken)

            validateStatusListTokenClaims(payload, statusListInfo, statusListToken)

            return extractTokenStatus(
                statusList = payload.statusList,
                statusListInfo = statusListInfo,
            )
        }

        /**
         * All existing claims in the Status List Token MUST be checked according to the rules in
         * Section 5.1 and Section 5.2
         *
         * The subject claim (sub or 2) of the Status List Token MUST be equal to the uri claim in the
         * status_list object of the Referenced Token
         *
         * If the Relying Party has custom policies regarding the freshness of the Status List Token,
         * it SHOULD check the issued at claim (iat or 6)
         *
         * If expiration time is defined (exp or 4), it MUST be checked if the Status List Token is
         * expired
         *
         * If the Relying Party is using a system for caching the Status List Token, it SHOULD
         * check the ttl claim of the Status List Token and retrieve a fresh copy if
         * (time status was resolved + ttl < current time)
         */
        private fun validateStatusListTokenClaims(
            statusListTokenPayload: StatusListTokenPayload,
            statusListInfo: StatusListInfo,
            statusListToken: StatusListToken,
        ) {
            if (statusListTokenPayload.subject.value != statusListInfo.uri.value) {
                throw IllegalStateException("The subject claim of the Status List Token is not equal to the uri claim in the status_list object of the Referenced Token.")
            }
            statusListTokenPayload.expirationTime?.let {
                if (isInstantInThePast(it.instant)) {
                    throw IllegalStateException("The status list token is expired.")
                }
            }
            statusListTokenPayload.timeToLive?.let { ttl ->
                extractStatusListTokenResolvedAt?.let {
                    val resolvedAt = it(statusListToken)
                    val validUntil = resolvedAt.plus(ttl.duration)

                    if (isInstantInThePast(validUntil)) {
                        throw IllegalStateException("The status list token is expired.")
                    }
                } ?: Napier.w("No status list token resolved timestamp was found despite a time to live claim.")
            }
        }

        /**
         * Decompress the Status List with a decompressor that is compatible with DEFLATE [RFC1951] and
         * ZLIB [RFC1950]
         *
         * Retrieve the status value of the index specified in the Referenced Token as described in
         * Section 4. Fail if the provided index is out of bound of the Status List
         */
        private fun extractTokenStatus(
            statusList: StatusList,
            statusListInfo: StatusListInfo,
        ): TokenStatus = statusList.toStatusListView().getOrNull(statusListInfo.idx.toLong())
            ?: throw IndexOutOfBoundsException("The index specified in the status list info is out of bounds of the status list.")
    }
}

