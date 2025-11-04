package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyStatusListTokenHAIP
import kotlin.time.Instant

sealed interface StatusListToken {
    val resolvedAt: Instant?
    val payload: StatusListTokenPayload

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

    data class StatusListJwt(
        val value: JwsSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken {
        override val payload: StatusListTokenPayload
            get() = value.payload

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
                StatusListTokenValidator.validateStatusListTokenPayloadClaims(
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
    ) : StatusListToken {
        override val payload: StatusListTokenPayload
            get() = value.payload ?: throw IllegalStateException("Payload not found.")

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
                StatusListTokenValidator.validateStatusListTokenPayloadClaims(
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
