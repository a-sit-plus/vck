package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.cosef.CoseSigned
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.RevocationListInfo
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import kotlinx.serialization.decodeFromByteArray
import kotlin.time.Instant

data class StatusListCwt(
    val value: CoseSigned<ByteArray>,
    override val resolvedAt: Instant?,
) : StatusListToken() {

    override val payload: KmmResult<StatusListTokenPayload>
        get() = catching { coseCompliantSerializer.decodeFromByteArray<StatusListTokenPayload>(value.payload!!) }

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
        verifyCoseSignature: VerifyCoseSignatureFun<ByteArray> = VerifyCoseSignature(),
        revocationListInfo: RevocationListInfo,
        isInstantInThePast: (Instant) -> Boolean,
    ): KmmResult<StatusListTokenPayload> = validateIntegrity(verifyCoseSignature, this).transform { payload ->
        validateStatusListTokenPayloadClaims(
            statusListTokenPayload = payload,
            statusListTokenResolvedAt = resolvedAt,
            revocationListInfo = revocationListInfo,
            isInstantInThePast = isInstantInThePast,
        )
    }

    /**
     * Validate the integrity of a status list cwt
     */
    private suspend fun validateIntegrity(
        verifyCoseSignature: VerifyCoseSignatureFun<ByteArray>,
        statusListToken: StatusListCwt
    ): KmmResult<StatusListTokenPayload> = catching {
        val coseStatus = statusListToken.value
        verifyCoseSignature(coseStatus, byteArrayOf(), null).getOrElse {
            throw IllegalStateException("Invalid Signature.", it)
        }
        val type = coseStatus.protectedHeader.type?.lowercase()
            ?: throw IllegalArgumentException("Invalid type header")
        if (type != MediaTypes.Application.STATUSLIST_CWT.lowercase()) {
            throw IllegalArgumentException("Invalid type header: $type")
        }
        coseCompliantSerializer.decodeFromByteArray<StatusListTokenPayload>(
            coseStatus.payload
                ?: throw IllegalStateException("Status list token payload not found.")
        )
    }
}
