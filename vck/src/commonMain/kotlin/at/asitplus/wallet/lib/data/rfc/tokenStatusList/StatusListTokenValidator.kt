package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.data.StatusListConstants
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.extensions.ifTrue
import at.asitplus.wallet.lib.extensions.toView
import kotlin.time.Instant

object StatusListTokenValidator {
    /**
     * Validate the Status List Token:
     *
     * Validate the Status List Token by following the rules defined in section 7.2 of [RFC7519]
     * for JWTs and section 7.2 of [RFC8392] for CWTs
     *
     * Check for the existence of the required claims as defined in Section 5.1 and Section 5.2
     * depending on token type.
     */
    suspend fun <S : StatusListToken> validateStatusListToken(
        statusListToken: S,
        statusListTokenResolvedAt: Instant?,
        validateStatusListTokenIntegrity: suspend (S) -> StatusListTokenPayload,
        statusListInfo: StatusListInfo,
        isInstantInThePast: (Instant) -> Boolean,
        /**
         * When using HAIP we need to provide trust anchors to verify the certificate chain
         */
        trustAnchors: Set<X509Certificate>? = null
    ): KmmResult<StatusListTokenPayload> = catching {
        if (statusListToken is StatusListToken.StatusListJwt) {
            val header = statusListToken.value.header
            require(header.type == StatusListConstants.STATUS_LIST_TYP) { "The JWT type MUST be statuslist+jwt" }
            if (trustAnchors != null) {
                require(header.certificateChain != null) { "The certificate chain must not be null when using HAIP" }
                require(
                    (header.certificateChain as Iterable<X509Certificate>).toSet().intersect(trustAnchors).isEmpty()
                ) { "The certificate chain must not contain any trusted certificates" }

                //TODO require cert path to trust anchor
                //TODO certs in certchain MUST not be self-signed
            }
        }
        val payload = validateStatusListTokenIntegrity(statusListToken)

        validateStatusListTokenPayloadClaims(
            statusListTokenPayload = payload,
            statusListInfo = statusListInfo,
            statusListTokenResolvedAt = statusListTokenResolvedAt,
            isInstantInThePast = isInstantInThePast,
        )

        payload
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
    fun validateStatusListTokenPayloadClaims(
        statusListTokenPayload: StatusListTokenPayload,
        statusListInfo: StatusListInfo,
        statusListTokenResolvedAt: Instant?,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<Unit> = catching {
        if (statusListTokenPayload.subject.string != statusListInfo.uri.string) {
            throw IllegalArgumentException("The subject claim of the Status List Token is not equal to the uri claim in the status_list object of the Referenced Token.")
        }
        statusListTokenPayload.expirationTime?.let(isInstantInThePast)?.ifTrue {
            throw IllegalStateException("The Status List Token is expired.")
        }
        statusListTokenPayload.timeToLive?.let { ttl ->
            statusListTokenResolvedAt?.let { resolvedAt ->
                if (isInstantInThePast(resolvedAt + ttl.duration)) {
                    throw IllegalStateException("The Status List Token is expired.")
                }
            }
        }
    }

    /**
     * Decompress the Status List with a decompressor that is compatible with DEFLATE [RFC1951] and
     * ZLIB [RFC1950]
     *
     * Retrieve the status value of the index specified in the Referenced Token as described in
     * Section 4. Fail if the provided index is out of bound of the Status List
     */
    fun extractTokenStatus(
        statusList: StatusList,
        statusListInfo: StatusListInfo,
        zlibService: ZlibService = DefaultZlibService(),
    ): KmmResult<TokenStatus> = catching {
        statusList.toView(zlibService).getOrNull(statusListInfo.index)
            ?: throw IndexOutOfBoundsException("The index specified in the status list info is out of bounds of the status list.")
    }

}