package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.extensions.ifTrue
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyStatusListTokenHAIP
import kotlin.time.Instant

sealed class StatusListToken {
    abstract val resolvedAt: Instant?
    abstract val payload: StatusListTokenPayload

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
        verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
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
    fun validateStatusListTokenPayloadClaims(
        statusListTokenPayload: StatusListTokenPayload,
        statusListInfo: StatusListInfo,
        statusListTokenResolvedAt: Instant?,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = catching {
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
        statusListTokenPayload
    }

    data class StatusListJwt(
        val value: JwsSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken() {
        override val payload = value.payload

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
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> =
            validateIntegrity(verifyJwsObject, this).transform { payload ->
                validateStatusListTokenPayloadClaims(
                    statusListTokenPayload = payload,
                    statusListTokenResolvedAt = resolvedAt,
                    statusListInfo = statusListInfo,
                    isInstantInThePast = isInstantInThePast,
                )
            }

        /**
         * Validate the integrity of a status list jwt
         */
        private suspend fun validateIntegrity(
            verifyJwsObject: VerifyJwsObjectFun,
            statusListToken: StatusListJwt
        ): KmmResult<StatusListTokenPayload> =
            catching {
                val jwsSigned = statusListToken.value
                verifyJwsObject(jwsSigned).getOrElse {
                    throw IllegalStateException(it)
                }
                val type = jwsSigned.header.type?.lowercase()
                    ?: throw IllegalArgumentException("Invalid type header")
                val validTypes = listOf(
                    MediaTypes.STATUSLIST_JWT.lowercase(),
                    MediaTypes.Application.STATUSLIST_JWT.lowercase()
                )
                if (type !in validTypes) {
                    throw IllegalArgumentException("Invalid type header: $type")
                }
                jwsSigned.payload
            }
    }

    data class StatusListCwt(
        val value: CoseSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken() {
        override val payload = value.payload ?: throw IllegalStateException("Payload not found.")

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
            verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> =
            validateIntegrity(verifyCoseSignature, this).transform { payload ->
                validateStatusListTokenPayloadClaims(
                    statusListTokenPayload = payload,
                    statusListTokenResolvedAt = resolvedAt,
                    statusListInfo = statusListInfo,
                    isInstantInThePast = isInstantInThePast,
                )
            }

        /**
         * Validate the integrity of a status list cwt
         */
        private suspend fun validateIntegrity(
            verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload>,
            statusListToken: StatusListCwt
        ): KmmResult<StatusListTokenPayload> =
            catching {
                val coseStatus = statusListToken.value
                verifyCoseSignature(coseStatus, byteArrayOf(), null).getOrElse {
                    throw IllegalStateException("Invalid Signature.", it)
                }
                val type = coseStatus.protectedHeader.type?.lowercase()
                    ?: throw IllegalArgumentException("Invalid type header")
                if (type != MediaTypes.Application.STATUSLIST_CWT.lowercase()) {
                    throw IllegalArgumentException("Invalid type header: $type")
                }
                coseStatus.payload
                    ?: throw IllegalStateException("Status list token payload not found.")
            }
    }
}
