package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.wallet.lib.validation.matchesDigest
import at.asitplus.signum.supreme.hash.digest
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.SuccessIso
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidator
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import io.github.aakira.napier.Napier
import kotlin.coroutines.cancellation.CancellationException
import kotlin.jvm.JvmOverloads

class ValidatorMdoc @JvmOverloads constructor(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    /**
     * Verifies the signature of the issuer on [IssuerSigned.issuerAuth], resolving the issuer key itself.
     * Pass [at.asitplus.wallet.lib.cbor.VerifyCoseSignatureTrustedCertificate] to require the issuer to be
     * trusted, the default only verifies against the certificate transported in the COSE headers.
     */
    private val verifyCoseSignature: VerifyCoseSignatureFun<MobileSecurityObject> =
        VerifyCoseSignature(VerifyCoseSignatureWithKey<MobileSecurityObject>(verifySignature)),
    /** Structure / Integrity / Semantics validator. */
    private val mdocInputValidator: MdocInputValidator =
        MdocInputValidator(verifyCoseSignature = verifyCoseSignature),
    private val validator: Validator = Validator(),
) {

    internal suspend fun checkRevocationStatus(issuerSigned: IssuerSigned) =
        validator.checkRevocationStatus(issuerSigned)

    /**
     * Validates an ISO device response, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDeviceResponse(
        deviceResponse: DeviceResponse,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): KmmResult<VerifyPresentationResult.SuccessIso> = catching {
        require(deviceResponse.status == 0U) { "status: ${deviceResponse.status}" }
        require(deviceResponse.documents != null) { "documents are null" }
        VerifyPresentationResult.SuccessIso(
            documents = deviceResponse.documents!!.map {
                verifyDocument(it, verifyDocumentCallback)
            }
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDocument(
        document: Document,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): IsoDocumentParsed {
        val documentErrors = document.errors.orEmpty()
        val issuerSigned = document.issuerSigned

        mdocInputValidator(issuerSigned).also {
            if (!it.isSuccess) {
                throw IllegalArgumentException("IssuerAuth not verified", it.error)
            }
        }

        val mso: MobileSecurityObject? = issuerSigned.issuerAuth.payload
        require(mso != null) { "mso is null" }
        require(mso.docType == document.docType) {
            "mso.docType '${mso.docType}' does not match Doc docType '${document.docType}'"
        }
        require(verifyDocumentCallback.invoke(mso, document)) {
            "document callback failed: $document"
        }

        val validItems = issuerSigned.namespaces?.flatMap { (namespace, issuerSignedItems) ->
            issuerSignedItems.entries.map {
                require(it.matchesDigest(mso.valueDigests[namespace], mso.digest)) {
                    "IssuerSigned item has invalid digest: ${it.value.elementIdentifier}"
                }
                it.value
            }
        }
        return IsoDocumentParsed(
            document = document,
            mso = mso,
            validItems = validItems.orEmpty(),
            freshnessSummary = validator.checkCredentialFreshness(issuerSigned),
            documentErrors = documentErrors,
        )
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    suspend fun verifyIsoCred(it: IssuerSigned) = catching {
        Napier.d("Verifying ISO Cred $it")
        val mdocInputValidator = mdocInputValidator(it)
        if (!mdocInputValidator.isSuccess) {
            throw mdocInputValidator.error ?: IllegalArgumentException("No details available")
        }
        SuccessIso(it)
    }
}
