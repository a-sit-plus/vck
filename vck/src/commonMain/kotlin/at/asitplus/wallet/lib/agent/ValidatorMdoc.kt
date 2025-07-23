package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.*
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidator
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
import kotlin.coroutines.cancellation.CancellationException

class ValidatorMdoc(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> =
        VerifyCoseSignatureWithKey(verifySignature),
    /** Structure / Integrity / Semantics validator. */
    private val mdocInputValidator: MdocInputValidator =
        MdocInputValidator(verifyCoseSignatureWithKey = verifyCoseSignatureWithKey),
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
    ): VerifyPresentationResult {
        if (deviceResponse.status != 0U) {
            Napier.w("Status invalid: ${deviceResponse.status}")
            throw IllegalArgumentException("status")
        }
        if (deviceResponse.documents == null) {
            Napier.w("No documents: $deviceResponse")
            throw IllegalArgumentException("documents")
        }
        return VerifyPresentationResult.SuccessIso(
            documents = deviceResponse.documents.map {
                verifyDocument(it, verifyDocumentCallback)
            }
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDocument(
        doc: Document,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): IsoDocumentParsed {
        if (doc.errors != null) {
            Napier.w("Document has errors: ${doc.errors}")
            throw IllegalArgumentException("errors")
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val certificateHead = issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull() ?: run {
            Napier.w("Got no issuer certificate in $issuerAuth")
            throw IllegalArgumentException("issuerKey")
        }
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
            Napier.w("Could not parse issuer certificate in ${certificateHead.encodeToString(Base64())}}", it)
            throw IllegalArgumentException("issuerKey")
        }
        val issuerKey = x509Certificate.publicKey.toCoseKey().getOrElse {
            Napier.w("Could not parse key from certificate in $x509Certificate", it)
            throw IllegalArgumentException("issuerKey")
        }

        verifyCoseSignatureWithKey(issuerAuth, issuerKey, byteArrayOf(), null).onFailure {
            Napier.w("IssuerAuth not verified: $issuerAuth", it)
            throw IllegalArgumentException("issuerAuth")
        }

        val mso: MobileSecurityObject? = issuerSigned.issuerAuth.payload
        if (mso == null) {
            Napier.w("MSO is null: $issuerAuth")
            throw IllegalArgumentException("mso")
        }

        if (mso.docType != doc.docType) {
            Napier.w("Invalid MSO docType '${mso.docType}' does not match Doc docType '${doc.docType}")
            throw IllegalArgumentException("mso.docType")
        }

        if (!verifyDocumentCallback.invoke(mso, doc)) {
            throw IllegalArgumentException("document callback failed: $doc")
        }

        val validItems = mutableListOf<IssuerSignedItem>()
        val invalidItems = mutableListOf<IssuerSignedItem>()
        issuerSigned.namespaces?.forEach { (namespace, issuerSignedItems) ->
            issuerSignedItems.entries.forEach {
                if (it.verify(mso.valueDigests[namespace])) {
                    validItems += it.value
                } else {
                    invalidItems += it.value
                }
            }
        }
        return IsoDocumentParsed(
            mso = mso,
            validItems = validItems,
            invalidItems = invalidItems,
            freshnessSummary = validator.checkCredentialFreshness(issuerSigned),
        )
    }

    /**
     * Verify that calculated digests equal the corresponding digest values in the MSO.
     *
     * See ISO/IEC 18013-5:2021, 9.3.1 Inspection procedure for issuer data authentication
     */
    private fun ByteStringWrapper<IssuerSignedItem>.verify(mdlItems: ValueDigestList?): Boolean {
        val issuerHash = mdlItems?.entries?.firstOrNull { it.key == value.digestId }
            ?: return false
        val verifierHash = coseCompliantSerializer
            .encodeToByteArray(ByteArraySerializer(), serialized)
            .wrapInCborTag(24)
            .sha256()
        if (!verifierHash.contentEquals(issuerHash.value)) {
            Napier.w("Could not verify hash of value for ${value.elementIdentifier}")
            return false
        }
        return true
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    suspend fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        if (!mdocInputValidator(it, issuerKey).isSuccess) {
            return InvalidStructure(coseCompliantSerializer.encodeToByteArray(it).encodeToString(Base16Strict))
        }
        return SuccessIso(it)
    }
}
