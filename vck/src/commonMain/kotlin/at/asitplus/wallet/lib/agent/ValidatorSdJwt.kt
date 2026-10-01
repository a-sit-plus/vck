package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.csc.contentEquals
import at.asitplus.iso.sha256
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.digest
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnf
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnfFun
import io.github.aakira.napier.Napier
import kotlin.jvm.JvmOverloads

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class ValidatorSdJwt @JvmOverloads constructor(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(verifyJwsSignature),
    /** Toggles whether transaction data should be verified if present. */
    private val verifyTransactionData: Boolean = true,
    /** Structure / Integrity / Semantics validator. */
    private val sdJwtInputValidator: SdJwtInputValidator = SdJwtInputValidator(verifyJwsObject = verifyJwsObject),
    private val validator: Validator = Validator(),
) {

    /**
     * Validates the content of a SD-JWT presentation, expected to contain a [VerifiableCredentialSdJwt],
     * as well as some disclosures and a key binding JWT at the end.
     *
     * @param challenge Expected challenge in the [KeyBindingJws] inside the [input]
     * @param audience Exact audience expected in the key binding JWT. Callers are responsible for supplying the
     * transport-specific value, such as an OpenID4VP Client Identifier or `origin:<origin>` for DC API transport.
     */
    suspend fun verifyVpSdJwt(
        input: SdJwtSigned,
        challenge: String,
        audience: String,
        transactionData: List<TransactionDataBase64Url>?,
        requireCryptographicHolderBinding: Boolean = true,
    ): KmmResult<VerifyPresentationResult.SuccessSdJwt> = catching {
        Napier.d("verifyVpSdJwt: '$input', '$challenge', '$audience', '$transactionData'")
        val sdJwtResult = verifySdJwt(input, null).getOrThrow()
        val vcSdJwt = sdJwtResult.verifiableCredentialSdJwt

        // verify if present or holder binding is required
        if (requireCryptographicHolderBinding && sdJwtResult.sdJwtSigned.keyBindingJws == null) {
            throw Throwable("No key binding JWT")
        }
        sdJwtResult.sdJwtSigned.keyBindingJws?.also { keyBindingSigned ->
            // The KB-JWT has to be verified against the key the issuer bound the credential to. Falling back to a key
            // asserted by the KB-JWT itself would prove nothing about the holder, so a missing cnf is an error.
            val confirmationClaim = vcSdJwt.confirmationClaim
                ?: throw Throwable("No cnf in SD-JWT to verify the key binding JWT against")
            if (!verifyJwsSignatureWithCnf(keyBindingSigned.jws, confirmationClaim)) {
                throw Throwable("Key binding JWT not verified (from cnf)")
            }

            val keyBinding = keyBindingSigned.payload
            require(keyBinding.challenge == challenge) {
                "Challenge not correct: ${keyBinding.challenge}"
            }
            require(keyBinding.audience == audience) {
                "Audience not correct: ${keyBinding.audience}"
            }

            val digest = vcSdJwt.selectiveDisclosureAlgorithm?.toDigest() ?: Digest.SHA256
            if (!keyBinding.sdHash.contentEquals(digest.digest(input.hashInput.encodeToByteArray()))) {
                throw Throwable("KB-JWT does not contain correct sd_hash")
            }

            if (verifyTransactionData) {
                transactionData?.let { data ->
                    val digests = data.map { it.digest(keyBinding.transactionDataHashesAlgorithm) }
                    if (keyBinding.transactionDataHashes?.contentEquals(digests) == false) {
                        throw Throwable("KB-JWT does not contain correct transaction data hashes")
                    }
                }
            }
        }

        Napier.d("verifyVpSdJwt: Valid")
        VerifyPresentationResult.SuccessSdJwt(
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
    ): KmmResult<VerifyCredentialResult.SuccessSdJwt> = catching {
        Napier.d("Verifying SD-JWT $sdJwtSigned for $publicKey")
        val validationResult = sdJwtInputValidator.invoke(sdJwtSigned, publicKey)
        return when {
            validationResult.integrityValidationResult.isFailure ->
                throw validationResult.integrityValidationResult.exceptionOrNull()!!

            validationResult.payloadCredentialValidationSummary.getOrNull()?.isSuccess == false
                -> throw IllegalArgumentException(
                "cnf claim invalid",
                validationResult.payloadCredentialValidationSummary.exceptionOrNull()
            )

            else -> validationResult.payload
        }
    }
}
