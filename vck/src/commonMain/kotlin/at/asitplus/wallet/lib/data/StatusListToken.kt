package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.StatusListTokenIntegrityValidator
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.third_party.kotlin.ifFalse
import at.asitplus.wallet.lib.jws.VerifierJwsService
import kotlinx.datetime.Instant

sealed interface StatusListToken {
    val resolvedAt: Instant?
    val payload: StatusListTokenPayload

    fun validate(
        verifierJwsService: VerifierJwsService,
        verifierCoseService: VerifierCoseService,
        statusListInfo: StatusListInfo,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
        statusListToken = this,
        statusListTokenResolvedAt = resolvedAt,
        validateStatusListTokenIntegrity = {
            StatusListTokenIntegrityValidator(
                verifierJwsService = verifierJwsService,
                verifierCoseService = verifierCoseService
            ).validateStatusListTokenIntegrity(it).getOrThrow()
        },
        statusListInfo = statusListInfo,
        isInstantInThePast = isInstantInThePast,
    )

    data class StatusListJwt(
        val value: JwsSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken {
        override val payload: StatusListTokenPayload
            get() = value.payload

        fun validate(
            verifierJwsService: VerifierJwsService,
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
            statusListToken = this,
            statusListTokenResolvedAt = resolvedAt,
            validateStatusListTokenIntegrity = { statusListToken ->
                val jwsSigned = statusListToken.value
                verifierJwsService.verifyJwsObject(jwsSigned).ifFalse {
                    throw IllegalStateException("Invalid Signature.")
                }

                if (jwsSigned.header.type?.lowercase() != MediaTypes.Application.STATUSLIST_JWT.lowercase()) {
                    throw IllegalArgumentException("Invalid type header")
                }
                jwsSigned.payload
            },
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast,
        )
    }

    data class StatusListCwt(
        val value: CoseSigned<StatusListTokenPayload>,
        override val resolvedAt: Instant?,
    ) : StatusListToken {
        override val payload: StatusListTokenPayload
            get() = value.payload ?: throw IllegalStateException("Payload not found.")

        fun validate(
            verifierCoseService: VerifierCoseService,
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
            statusListToken = this,
            statusListTokenResolvedAt = resolvedAt,
            validateStatusListTokenIntegrity = { statusListToken ->
                val coseStatus = statusListToken.value
                verifierCoseService.verifyCose(
                    coseSigned = coseStatus,
                    serializer = StatusListTokenPayload.serializer(),
                ).isSuccess.ifFalse {
                    throw IllegalStateException("Invalid Signature.")
                }
                if (coseStatus.protectedHeader.type?.lowercase() != MediaTypes.Application.STATUSLIST_CWT.lowercase()) {
                    throw IllegalArgumentException("Invalid type header")
                }
                coseStatus.payload
                    ?: throw IllegalStateException("Status list token payload not found.")
            },
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast,
        )
    }
}