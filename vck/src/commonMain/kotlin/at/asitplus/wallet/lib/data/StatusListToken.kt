package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.StatusListTokenIntegrityValidator
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.third_party.kotlin.ifFalse
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import kotlinx.datetime.Instant

sealed interface StatusListToken {
    val resolvedAt: Instant?
    val payload: StatusListTokenPayload

    @Deprecated("Use validate with verifyJwsSignatureObject instead")
    suspend fun validate(
        verifierJwsService: VerifierJwsService,
        verifierCoseService: VerifierCoseService,
        statusListInfo: StatusListInfo,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
        statusListToken = this,
        statusListTokenResolvedAt = resolvedAt,
        validateStatusListTokenIntegrity = {
            StatusListTokenIntegrityValidator(
                verifyJwsObject = verifierJwsService::verifyJwsObject,
                verifyCoseSignature = verifierCoseService::verifyCose,
            ).validateStatusListTokenIntegrity(it).getOrThrow()
        },
        statusListInfo = statusListInfo,
        isInstantInThePast = isInstantInThePast,
    )


    suspend fun validate(
        verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
        verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
        statusListInfo: StatusListInfo,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
        statusListToken = this,
        statusListTokenResolvedAt = resolvedAt,
        validateStatusListTokenIntegrity = {
            StatusListTokenIntegrityValidator(
                verifyJwsObject = verifyJwsObject,
                verifyCoseSignature = verifyCoseSignature,
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

        @Deprecated("Use validate with verifyJwsSignatureObject instead")
        suspend fun validate(
            verifierJwsService: VerifierJwsService,
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
            statusListToken = this,
            statusListTokenResolvedAt = resolvedAt,
            validateStatusListTokenIntegrity = {
                StatusListTokenIntegrityValidator(
                    verifyJwsObject = verifierJwsService::verifyJwsObject,
                    verifyCoseSignature = { _, _, _ -> KmmResult.failure(IllegalArgumentException("CWT not expected")) }
                ).validateStatusListTokenIntegrity(it).getOrThrow()
            },
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast,
        )

        suspend fun validate(
            verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
            statusListToken = this,
            statusListTokenResolvedAt = resolvedAt,
            validateStatusListTokenIntegrity = {
                StatusListTokenIntegrityValidator(
                    verifyJwsObject = verifyJwsObject,
                    verifyCoseSignature = { _, _, _ -> KmmResult.failure(IllegalArgumentException("CWT not expected")) },
                ).validateStatusListTokenIntegrity(it).getOrThrow()
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

        suspend fun validate(
            verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
            statusListInfo: StatusListInfo,
            isInstantInThePast: (Instant) -> Boolean,
        ): KmmResult<StatusListTokenPayload> = StatusListTokenValidator.validateStatusListToken(
            statusListToken = this,
            statusListTokenResolvedAt = resolvedAt,
            validateStatusListTokenIntegrity = {
                StatusListTokenIntegrityValidator(
                    verifyJwsObject = { false },
                    verifyCoseSignature = verifyCoseSignature,
                ).validateStatusListTokenIntegrity(it).getOrThrow()
            },
            statusListInfo = statusListInfo,
            isInstantInThePast = isInstantInThePast,
        )
    }
}
