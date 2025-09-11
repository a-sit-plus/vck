package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidationSummary.IntegrityValidationSummary
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import io.github.aakira.napier.Napier

class MdocInputValidator(
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> =
        VerifyCoseSignatureWithKey(),
) {
    suspend operator fun invoke(it: IssuerSigned, issuerKey: CoseKey?) = MdocInputValidationSummary(
        integrityValidationSummary = if (issuerKey == null) {
            IntegrityValidationSummary.IntegrityNotValidated
        } else {
            val verifyCoseSignatureWithKey = verifyCoseSignatureWithKey(it.issuerAuth, issuerKey, byteArrayOf(), null)
            IntegrityValidationSummary.IntegrityValidationResult(
                issuerKey = issuerKey,
                isSuccess = verifyCoseSignatureWithKey.isSuccess,
                error = verifyCoseSignatureWithKey.exceptionOrNull(),
            )
        },
    ).also {
        Napier.d("MdocInputValidator: Result: $it")
    }
}

