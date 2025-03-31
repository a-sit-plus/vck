package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.MediaTypes
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.third_party.kotlin.ifFalse
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun

/**
 * Parses and validates Status List Tokens
 * Does verify the cryptographic authenticity of the data.
 */
class StatusListTokenIntegrityValidator(
    @Deprecated("Use verifyJwsSignatureObject instead")
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(),
) {
    /**
     * Validate the integrity of a status list token
     */
    suspend fun validateStatusListTokenIntegrity(statusListToken: StatusListToken) =
        when (val it = statusListToken) {
            is StatusListToken.StatusListJwt -> validateStatusListJwtIntegrity(it)
            is StatusListToken.StatusListCwt -> validateStatusListCwtIntegrity(it)
        }

    /**
     * Validate the integrity of a status list jwt
     */
    suspend fun validateStatusListJwtIntegrity(statusListToken: StatusListToken.StatusListJwt): KmmResult<StatusListTokenPayload> =
        catching {
            val jwsSigned = statusListToken.value
            verifyJwsObject(jwsSigned).ifFalse {
                throw IllegalStateException("Invalid Signature.")
            }

            if (jwsSigned.header.type?.lowercase() != MediaTypes.Application.STATUSLIST_JWT.lowercase()) {
                throw IllegalArgumentException("Invalid type header")
            }
            jwsSigned.payload
        }

    /**
     * Validate the integrity of a status list cwt
     */
    fun validateStatusListCwtIntegrity(statusListToken: StatusListToken.StatusListCwt): KmmResult<StatusListTokenPayload> =
        catching {
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
        }
}

/**
 * Parses and validates Status List Tokens
 * Does verify the cryptographic authenticity of the data.
 */
class StatusListJwtIntegrityValidator(
    @Deprecated("Use verifyJwsSignatureObject instead")
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(),
) {
    /**
     * Validate the integrity of a status list token
     */
    suspend fun validateStatusListTokenIntegrity(statusListToken: StatusListToken) =
        when (val it = statusListToken) {
            is StatusListToken.StatusListJwt -> validateStatusListJwtIntegrity(it)
            is StatusListToken.StatusListCwt -> validateStatusListCwtIntegrity(it)
        }

    /**
     * Validate the integrity of a status list jwt
     */
    suspend fun validateStatusListJwtIntegrity(statusListToken: StatusListToken.StatusListJwt): KmmResult<StatusListTokenPayload> =
        catching {
            val jwsSigned = statusListToken.value
            verifyJwsObject(jwsSigned).ifFalse {
                throw IllegalStateException("Invalid Signature.")
            }

            if (jwsSigned.header.type?.lowercase() != MediaTypes.Application.STATUSLIST_JWT.lowercase()) {
                throw IllegalArgumentException("Invalid type header")
            }
            jwsSigned.payload
        }

    /**
     * Validate the integrity of a status list cwt
     */
    fun validateStatusListCwtIntegrity(statusListToken: StatusListToken.StatusListCwt): KmmResult<StatusListTokenPayload> =
        catching {
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
        }
}
