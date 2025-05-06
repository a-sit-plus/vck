package at.asitplus.wallet.lib.agent.validation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.agent.matchesIdentifier
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun

data class VerifiableCredentialJwsInputValidator(
    val verifiableCredentialJwsContentSemanticsValidator: VerifiableCredentialJwsContentSemanticsValidator = VerifiableCredentialJwsContentSemanticsValidator(),
    val jwsIntegrityValidator: VerifyJwsObjectFun = VerifyJwsObject(),
//    val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator = VerifiableCredentialJwsTimelinessValidator(),
//    val tokenStatusResolver: TokenStatusResolver,
) {
    suspend fun validate(
        input: String,
        publicKey: CryptoPublicKey?,
    ): VerifiableCredentialJwsInputValidationResult {
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
            return VerifiableCredentialJwsInputValidationResult.ParsingError(input, it)
        }
        val vcJws = jws.payload
        return VerifiableCredentialJwsInputValidationResult.ContentValidationSummary(
            input = input,
            parsed = jws,
            isIntegrityGood = jwsIntegrityValidator(jws),
            subjectMatchingResult = publicKey?.let {
                VerifiableCredentialJwsInputValidationResult.ContentValidationSummary.SubjectMatchingResult(
                    subject = vcJws.subject,
                    publicKey = publicKey,
                    isSuccess = it.matchesIdentifier(vcJws.subject)
                )
            },
            contentSemanticsValidationSummary = verifiableCredentialJwsContentSemanticsValidator.validate(vcJws),
//            timelinessValidationSummary = verifiableCredentialJwsTimelinessValidator.validate(vcJws),
//            tokenStatusValidationSummary = vcJws.vc.credentialStatus?.let {
//                Napier.d("VC: status found")
//                TokenStatusValidationSummary(
//                    status = it,
//                    tokenStatus = tokenStatusValidator(it)
//                )
//            },
        )
    }
}

