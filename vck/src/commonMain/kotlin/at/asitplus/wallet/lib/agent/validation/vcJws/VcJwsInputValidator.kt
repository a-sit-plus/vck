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
    val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
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
            isIntegrityGood = verifyJwsObject(jws),
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

sealed interface VcJwsInputValidationResult {
    val isSuccess: Boolean

    data class ParsingError(
        val input: String,
        val throwable: Throwable,
    ) : VcJwsInputValidationResult {
        override val isSuccess: Boolean
            get() = false
    }

    data class ContentValidationSummary(
        val input: String,
        val parsed: JwsSigned<VerifiableCredentialJws>,
        val isIntegrityGood: Boolean,
        val subjectMatchingResult: SubjectMatchingResult?,
        val contentSemanticsValidationSummary: VcJwsContentSemanticsValidationSummary,
    ) : VcJwsInputValidationResult {
        val payload: VerifiableCredentialJws
            get() = parsed.payload

        override val isSuccess: Boolean
            get() = listOf(
                isIntegrityGood,
                subjectMatchingResult?.isSuccess != false,
                contentSemanticsValidationSummary.isSuccess,
            ).all { it }
    }
}

