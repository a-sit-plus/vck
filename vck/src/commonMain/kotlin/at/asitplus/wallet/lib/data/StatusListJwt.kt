package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import kotlin.time.Instant

data class StatusListJwt(
    val value: JwsSigned<StatusListTokenPayload>,
    override val resolvedAt: Instant?,
) : StatusListToken() {

    override val payload: KmmResult<StatusListTokenPayload> = KmmResult.success(value.payload)

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
        /** When using HAIP use [VerifyStatusListTokenHAIP] otherwise [VerifyJwsObject] is sufficient */
        verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
        revocationListInfo: RevocationListInfo,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = validateIntegrity(verifyJwsObject, this).transform { payload ->
        validateStatusListTokenPayloadClaims(
            statusListTokenPayload = payload,
            statusListTokenResolvedAt = resolvedAt,
            revocationListInfo = revocationListInfo,
            isInstantInThePast = isInstantInThePast,
        )
    }

    /**
     * Validate the integrity of a status list jwt
     */
    private suspend fun validateIntegrity(
        verifyJwsObject: VerifyJwsObjectFun,
        statusListToken: StatusListJwt
    ): KmmResult<StatusListTokenPayload> = catching {
        val jwsSigned = statusListToken.value
        verifyJwsObject(jwsSigned).getOrElse {
            throw IllegalStateException("Invalid signature", it)
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