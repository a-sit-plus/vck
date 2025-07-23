package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import io.github.aakira.napier.Napier

class MdocInputValidator(
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> =
        VerifyCoseSignatureWithKey(),
) {
    suspend operator fun invoke(it: IssuerSigned, issuerKey: CoseKey?) = MdocInputValidationSummary(
        integrityValidationSummary = if (issuerKey == null) {
            Napier.w("ISO: No issuer key")
            MdocInputValidationSummary.IntegrityValidationSummary.IntegrityNotValidated
        } else {
            MdocInputValidationSummary.IntegrityValidationSummary.IntegrityValidationResult(
                issuerKey = issuerKey,
                isSuccess = verifyCoseSignatureWithKey(it.issuerAuth, issuerKey, byteArrayOf(), null).onFailure { ex ->
                    Napier.w("ISO: Could not verify credential", ex)
                }.isSuccess
            )
        },
    ).also {
        if (it.isSuccess) {
            Napier.d("Verifying ISO Cred $it")
        }
    }
}

