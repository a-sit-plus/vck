package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.extensions.ifFalse
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun

/**
 * Parses and validates Status List Tokens
 * Does verify the cryptographic authenticity of the data.
 */
interface StatusListTokenIntegrityValidator<T: StatusListToken> {
    /**
     * Validate the integrity of a status list token
     */
    suspend fun validateStatusListTokenIntegrity(statusListToken: T): KmmResult<StatusListTokenPayload>
}

class StatusListJwtIntegrityValidator(
    val verifyJwsObject: VerifyJwsObjectFun
): StatusListTokenIntegrityValidator<StatusListToken.StatusListJwt> {
    /**
     * Validate the integrity of a status list jwt
     */
    override suspend fun validateStatusListTokenIntegrity(statusListToken: StatusListToken.StatusListJwt): KmmResult<StatusListTokenPayload> =
        catching {
            val jwsSigned = statusListToken.value
            verifyJwsObject(jwsSigned).ifFalse {
                throw IllegalStateException("Invalid Signature.")
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

class StatusListCwtIntegrityValidator(
    val verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature()
) : StatusListTokenIntegrityValidator<StatusListToken.StatusListCwt> {

    /**
     * Validate the integrity of a status list cwt
     */
    override suspend fun validateStatusListTokenIntegrity(statusListToken: StatusListToken.StatusListCwt): KmmResult<StatusListTokenPayload> =
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

