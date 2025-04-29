package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.Configuration
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import io.github.aakira.napier.Napier

data class VerifiableCredentialJwsInputValidator(
    val verifiableCredentialJwsStructureValidator: VerifiableCredentialJwsStructureValidator = Configuration.instance.verifiableCredentialJwsStructureValidator,
    val verifiableCredentialJwsTimelinessValidator: VerifiableCredentialJwsTimelinessValidator = Configuration.instance.verifiableCredentialJwsTimelinessValidator,
    val verifyJwsObject: VerifyJwsObjectFun = Configuration.instance.verifyJwsObjectFun,
    val checkRevocationStatus: suspend (Status) -> KmmResult<TokenStatus>,
) {
    suspend fun validate(
        input: String,
        publicKey: CryptoPublicKey?,
    ): VerifiableCredentialJwsValidationResult {
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
            return VerifiableCredentialJwsValidationResult.ParsingError(
                input,
                it,
            )
        }
        val vcJws = jws.payload
        return VerifiableCredentialJwsValidationResult.ValidationSummary(
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
            structureValidationSummary = verifiableCredentialJwsStructureValidator.validate(vcJws),
            timelinessValidationSummary = verifiableCredentialJwsTimelinessValidator.validate(vcJws),
            tokenStatusValidationSummary = vcJws.vc.credentialStatus?.let {
                Napier.d("VC: status found")
                TokenStatusValidationSummary(
                    status = it,
                    tokenStatus = checkRevocationStatus(it)
                )
            },
        )
    }

    sealed interface VerifiableCredentialJwsValidationResult {
        val isSuccess: Boolean

        data class ParsingError(
            val input: String,
            val throwable: Throwable,
        ) : VerifiableCredentialJwsValidationResult {
            override val isSuccess: Boolean
                get() = false
        }

        data class ValidationSummary(
            val input: String,
            val parsed: JwsSigned<VerifiableCredentialJws>,
            val isIntegrityGood: Boolean,
            val subjectMatchingResult: SubjectMatchingResult?,
            val structureValidationSummary: VerifiableCredentialJwsStructureValidator.ValidationSummary,
            val timelinessValidationSummary: VerifiableCredentialJwsTimelinessValidator.ValidationSummary,
            val tokenStatusValidationSummary: TokenStatusValidationSummary?,
        ) : VerifiableCredentialJwsValidationResult {
            val payload: VerifiableCredentialJws
                get() = parsed.payload

            override val isSuccess: Boolean
                get() = listOf(
                    isIntegrityGood,
                    subjectMatchingResult?.isSuccess != false,
                    structureValidationSummary.isSuccess,
                    timelinessValidationSummary.isSuccess,
                    tokenStatusValidationSummary?.tokenStatus?.let {
                        it.getOrNull()?.let {
                            it != TokenStatus.Invalid
                        } ?: false
                    } ?: false,
                ).all { it }
        }
    }

    data class SubjectMatchingResult(
        val subject: String,
        val publicKey: CryptoPublicKey,
        val isSuccess: Boolean,
    )
}