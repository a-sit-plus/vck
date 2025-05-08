package at.asitplus.wallet.lib.agent.validation.vcJws

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.agent.validation.common.SubjectMatchingResult
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun

data class VcJwsInputValidator(
    val vcJwsContentSemanticsValidator: VcJwsContentSemanticsValidator = VcJwsContentSemanticsValidator(),
    val jwsIntegrityValidator: VerifyJwsObjectFun = VerifyJwsObject(),
) {
    suspend operator fun invoke(
        input: String,
        publicKey: CryptoPublicKey?,
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
            isIntegrityGood = jwsIntegrityValidator(jws),
            subjectMatchingResult = publicKey?.let {
                SubjectMatchingResult(
                    subject = vcJws.subject,
                    publicKey = publicKey,
                    isSuccess = it.matchesIdentifier(vcJws.subject)
                )
            },
            contentSemanticsValidationSummary = vcJwsContentSemanticsValidator.invoke(vcJws),
        )
    }
}

