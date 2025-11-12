package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun

data class VcJwsInputValidator(
    val vcJwsContentSemanticsValidator: VcJwsContentSemanticsValidator = VcJwsContentSemanticsValidator(),
    val vpJwsMapsToVpJwsValidator: VcJwsToVpJwsMappingValidator = VcJwsToVpJwsMappingValidator(),
    val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
) {
    suspend operator fun invoke(
        input: String,
        publicKey: CryptoPublicKey?,
        vpJws: JwsSigned<VerifiablePresentationJws>?,
    ): VcJwsInputValidationResult {
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
            return VcJwsInputValidationResult.ParsingError(input, it)
        }
        val vcJws = jws.payload

        return VcJwsInputValidationResult.ContentValidationSummary(
            input = input,
            parsed = jws,
            isIntegrityGood = verifyJwsObject(jws).isSuccess,
            subjectMatchingResult = publicKey?.let {
                SubjectMatchingResult(
                    subject = vcJws.subject,
                    publicKey = publicKey,
                    isSuccess = it.matchesIdentifier(vcJws.subject)
                )
            },
            contentSemanticsValidationSummary = vcJwsContentSemanticsValidator.invoke(vcJws),
            vpMappingValidationSummary = vpJws?.let { vpJwsMapsToVpJwsValidator.invoke(vcJws, vpJws) }
        )
    }
}

