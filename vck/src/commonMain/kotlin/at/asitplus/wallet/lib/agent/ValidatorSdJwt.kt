package at.asitplus.wallet.lib.agent

import at.asitplus.iso.sha256
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.rqes.contentEquals
import at.asitplus.openid.sha256
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.SuccessSdJwt
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.ValidationError
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.*
import io.github.aakira.napier.Napier

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class ValidatorSdJwt(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(verifyJwsSignature),
    /** Toggles whether transaction data should be verified if present. */
    private val verifyTransactionData: Boolean = true,
    /** Structure / Integrity / Semantics validator. */
    private val sdJwtInputValidator: SdJwtInputValidator =
        SdJwtInputValidator(verifyJwsObject = verifyJwsObject),
    private val validator: Validator = Validator(),
) {

    /**
     * Validates the content of a SD-JWT presentation, expected to contain a [VerifiableCredentialSdJwt],
     * as well as some disclosures and a key binding JWT at the end.
     *
     * @param challenge Expected challenge in the [KeyBindingJws] inside the [input]
     * @param clientId Identifier of the verifier, to verify audience of key binding JWS
     */
    suspend fun verifyVpSdJwt(
        input: SdJwtSigned,
        challenge: String,
        clientId: String,
        transactionData: List<TransactionDataBase64Url>?,
    ): VerifyPresentationResult {
        Napier.d("verifyVpSdJwt: '$input', '$challenge', '$clientId', '$transactionData'")
        val sdJwtResult = verifySdJwt(input, null)
        if (sdJwtResult !is SuccessSdJwt) {
            Napier.w("verifyVpSdJwt: Could not verify SD-JWT: $sdJwtResult")
            val error = (sdJwtResult as? ValidationError)?.cause
                ?: Throwable("SD-JWT not verified")
            return VerifyPresentationResult.ValidationError(error)
        }
        val keyBindingSigned = sdJwtResult.sdJwtSigned.keyBindingJws ?: run {
            Napier.w("verifyVpSdJwt: No key binding JWT")
            return VerifyPresentationResult.ValidationError("No key binding JWT")
        }
        val vcSdJwt = sdJwtResult.verifiableCredentialSdJwt
        vcSdJwt.confirmationClaim?.let {
            if (!verifyJwsSignatureWithCnf(keyBindingSigned, it)) {
                Napier.w("verifyVpSdJwt: Key binding JWT not verified with keys from cnf")
                return VerifyPresentationResult.ValidationError("Key binding JWT not verified (from cnf)")
            }
        } ?: run {
            if (!verifyJwsObject(keyBindingSigned)) {
                Napier.w("verifyVpSdJwt: Key binding JWT not verified")
                return VerifyPresentationResult.ValidationError("Key binding JWT not verified")
            }
        }
        val keyBinding = keyBindingSigned.payload

        if (keyBinding.challenge != challenge) {
            Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}, expected $clientId")
            return VerifyPresentationResult.ValidationError("Challenge not correct: ${keyBinding.challenge}")
        }
        if (keyBinding.audience != clientId) {
            Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}, expected $clientId")
            return VerifyPresentationResult.ValidationError("Audience not correct: ${keyBinding.audience}")
        }
        if (!keyBinding.sdHash.contentEquals(input.hashInput.encodeToByteArray().sha256())) {
            Napier.w("verifyVpSdJwt: Key Binding does not contain correct sd_hash")
            return VerifyPresentationResult.ValidationError("Key Binding does not contain correct sd_hash")
        }
        if (verifyTransactionData) {
            transactionData?.let { data ->
                //TODO support more hash algorithms
                if (keyBinding.transactionDataHashesAlgorithm != "sha-256") {
                    Napier.w("verifyVpSdJwt: Key Binding uses unsupported hashing algorithm. Please use sha256")
                    return VerifyPresentationResult.ValidationError("verifyVpSdJwt: Key Binding uses unsupported hashing algorithm. Please use sha256")
                }
                if (keyBinding.transactionDataHashes?.contentEquals(data.map { it.sha256() }) == false) {
                    Napier.w("verifyVpSdJwt: Key Binding does not contain correct transaction data hashes")
                    return VerifyPresentationResult.ValidationError("Key Binding does not contain correct transaction data hashes")
                }
            }
        }

        Napier.d("verifyVpSdJwt: Valid")
        return VerifyPresentationResult.SuccessSdJwt(
            sdJwtSigned = sdJwtResult.sdJwtSigned,
            verifiableCredentialSdJwt = vcSdJwt,
            reconstructedJsonObject = sdJwtResult.reconstructedJsonObject,
            disclosures = sdJwtResult.disclosures.values,
            freshnessSummary = validator.checkCredentialFreshness(sdJwtResult.verifiableCredentialSdJwt),
        )
    }

    /**
     * Validates the content of an [SdJwtSigned], expected to contain a [VerifiableCredentialSdJwt].
     *
     * @param publicKey Optionally, the local key, to verify SD-JWT was bound to it
     */
    suspend fun verifySdJwt(
        sdJwtSigned: SdJwtSigned,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $sdJwtSigned for $publicKey")
        val validationResult = sdJwtInputValidator.invoke(sdJwtSigned, publicKey)
        return when {
            !validationResult.isIntegrityGood -> ValidationError("Signature not verified")
            validationResult.payloadCredentialValidationSummary.getOrNull()?.isSuccess == false
                -> ValidationError("cnf claim invalid")

            else -> validationResult.payload.getOrElse { return ValidationError(it) }
        }
    }

}
