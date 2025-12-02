package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.IdentifierListInfo
import at.asitplus.wallet.lib.extensions.ifTrue
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import kotlin.time.Instant

sealed class StatusListToken {
    abstract val resolvedAt: Instant?
    abstract val payload: KmmResult<StatusListTokenPayload>

    /**
     * Validate the Status List Token:
     *
     * Validate the Status List Token by following the rules defined in section 7.2 of [RFC7519]
     * for JWTs and section 7.2 of [RFC8392] for CWTs
     *
     * Check for the existence of the required claims as defined in Section 5.1 and Section 5.2
     * depending on token type.
     */
    suspend fun validate(
        verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
        verifyCoseSignature: VerifyCoseSignatureFun<ByteArray> = VerifyCoseSignature(),
        statusListInfo: StatusListInfo,
        isInstantInThePast: (Instant) -> Boolean
    ): KmmResult<StatusListTokenPayload> = when (this) {
        is StatusListJwt -> validate(
            verifyJwsObject = verifyJwsObject,
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast
        )

        is StatusListCwt -> validate(
            verifyCoseSignature = verifyCoseSignature,
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast
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
    internal fun validateStatusListTokenPayloadClaims(
        statusListTokenPayload: StatusListTokenPayload,
        statusListInfo: StatusListInfo? = null,
        identifierListInfo: IdentifierListInfo? = null,
        statusListTokenResolvedAt: Instant?,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = catching {
        if (statusListInfo != null && statusListTokenPayload.subject.string != statusListInfo.uri.string) {
            throw IllegalArgumentException("The subject claim of the Status List Token is not equal to the uri claim in the status_list object of the Referenced Token.")
        }
        if (identifierListInfo != null && statusListTokenPayload.subject.string != identifierListInfo.uri.string) {
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
        statusListTokenPayload
    }
}
