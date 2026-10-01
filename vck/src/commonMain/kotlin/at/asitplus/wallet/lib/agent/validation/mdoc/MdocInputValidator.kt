package at.asitplus.wallet.lib.agent.validation.mdoc

import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidationSummary.IntegrityValidationSummary
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import io.github.aakira.napier.Napier

class MdocInputValidator(
    /**
     * Verifies the signature of the issuer on [IssuerSigned.issuerAuth], resolving the issuer key itself.
     * Pass [at.asitplus.wallet.lib.cbor.VerifyCoseSignatureTrustedCertificate] to require the issuer to be
     * trusted, the default only verifies against the certificate transported in the COSE headers.
     */
    private val verifyCoseSignature: VerifyCoseSignatureFun<MobileSecurityObject> = VerifyCoseSignature(),
) {
    suspend operator fun invoke(it: IssuerSigned) = MdocInputValidationSummary(
        integrityValidationSummary = verifyCoseSignature(it.issuerAuth, byteArrayOf(), null).let { result ->
            IntegrityValidationSummary.IntegrityValidationResult(
                isSuccess = result.isSuccess,
                error = result.exceptionOrNull(),
            )
        },
    ).also {
        Napier.d("MdocInputValidator: Result: $it")
    }
}
