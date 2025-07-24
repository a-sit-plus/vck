package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.*
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_PRESENTATION
import at.asitplus.wallet.lib.jws.*
import io.github.aakira.napier.Napier
import kotlin.coroutines.cancellation.CancellationException

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class ValidatorVcJws(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    /** Structure / Integrity / Semantics validator. */
    private val vcJwsInputValidator: VcJwsInputValidator =
        VcJwsInputValidator(verifyJwsObject = verifyJwsObject),
    private val validator: Validator = Validator(),
) {
    internal fun checkCredentialTimeliness(vcJws: VerifiableCredentialJws) =
        validator.checkCredentialTimeliness(vcJws)

    suspend fun checkCredentialFreshness(vcJws: VerifiableCredentialJws) =
        validator.checkCredentialFreshness(vcJws)

    internal suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws) =
        validator.checkRevocationStatus(vcJws)

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Presentation.
     *
     * @param challenge Nonce that the verifier has sent to the holder
     * @param clientId Identifier of the verifier (i.e. the audience of the presentation)
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyVpJws(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
        clientId: String,
    ): VerifyPresentationResult {
        Napier.d("Verifying VP $input with $challenge and $clientId")
        if (!verifyJwsObject(input)) {
            Napier.w("VP: Signature invalid")
            throw IllegalArgumentException("signature")
        }
        val vpJws = input.payload.validate(challenge, clientId)
        val vcValidationResults = vpJws.vp.verifiableCredential
            .map { it to verifyVcJws(it, null) }

        val invalidVcList = vcValidationResults.filter {
            it.second !is SuccessJwt
        }.map {
            it.first
        }

        val verificationResultWithFreshnessSummary = vcValidationResults.map {
            it.second
        }.filterIsInstance<SuccessJwt>().map {
            it.jws
        }.map {
            VcJwsVerificationResultWrapper(
                vcJws = it,
                freshnessSummary = validator.checkCredentialFreshness(it),
            )
        }

        val vp = VerifiablePresentationParsed(
            jws = input,
            id = vpJws.vp.id,
            type = vpJws.vp.type,
            freshVerifiableCredentials = verificationResultWithFreshnessSummary.filter {
                it.freshnessSummary.isFresh
            },
            notVerifiablyFreshVerifiableCredentials = verificationResultWithFreshnessSummary.filter {
                !it.freshnessSummary.isFresh
            },
            invalidVerifiableCredentials = invalidVcList,
        )
        Napier.d("VP: Valid")

        return VerifyPresentationResult.Success(vp)
    }

    @Throws(IllegalArgumentException::class)
    fun VerifiablePresentationJws.validate(
        challenge: String,
        clientId: String,
    ): VerifiablePresentationJws {
        if (this.challenge != challenge) {
            Napier.w("nonce invalid")
            throw IllegalArgumentException("nonce invalid")
        }
        if (clientId != audience) {
            Napier.w("aud invalid: ${audience}, expected $clientId}")
            throw IllegalArgumentException("aud invalid: $audience")
        }
        if (jwtId != vp.id) {
            Napier.w("jti invalid: ${jwtId}, expected ${vp.id}")
            throw IllegalArgumentException("jti invalid: $jwtId")
        }
        if (vp.type != VERIFIABLE_PRESENTATION) {
            Napier.w("type invalid: ${vp.type}, expected $VERIFIABLE_PRESENTATION")
            throw IllegalArgumentException("type invalid: ${vp.type}")
        }
        Napier.d("VP is valid")
        return this
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally, the local key, to verify VC was issued to the correct subject
     */
    suspend fun verifyVcJws(
        input: JwsSigned<VerifiableCredentialJws>,
        publicKey: CryptoPublicKey?,
    ) = verifyVcJws(input.serialize(), publicKey)

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally, the local key, to verify VC was issued to the correct subject
     */
    suspend fun verifyVcJws(
        input: String,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult {
        Napier.d("Validating VC-JWS $input")
        val validationSummary = vcJwsInputValidator(input, publicKey)
        return when {
            validationSummary !is VcJwsInputValidationResult.ContentValidationSummary -> InvalidStructure(input)
            !validationSummary.isIntegrityGood -> InvalidStructure(input)
            !validationSummary.contentSemanticsValidationSummary.isSuccess -> InvalidStructure(input)
            validationSummary.subjectMatchingResult?.isSuccess == false -> ValidationError("subject not matching key")
            validationSummary.isSuccess -> SuccessJwt(validationSummary.payload)
            else -> ValidationError(input) // this branch shouldn't be executed anyway
        }
    }

}
