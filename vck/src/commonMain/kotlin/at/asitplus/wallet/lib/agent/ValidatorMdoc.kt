package at.asitplus.wallet.lib.agent

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSignedItem
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.SuccessIso
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidator
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationDetails
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.IsoPlainDocumentParsed
import at.asitplus.wallet.lib.data.IsoZkDocumentParsed
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.builtins.ByteArraySerializer
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
        verifyPlainDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
        verifyZkDocumentCallback: ((ZkDocument) -> Boolean)? = null,
    ): VerifyPresentationResult {
        require(deviceResponse.status == 0U) { "status: ${deviceResponse.status}" }
        require(deviceResponse.documents != null || deviceResponse.zkDocuments != null) {
            "documents and zkDocuments are null"
        }
        val hasZkDocuments = !deviceResponse.zkDocuments.isNullOrEmpty()

        if (hasZkDocuments && verifyZkDocumentCallback == null) {
            throw IllegalArgumentException("ZkDocuments in response, but no validation possible")
        }

        val plainDocuments = deviceResponse.documents?.map {
            verifyPlainDocument(it, verifyPlainDocumentCallback)
        } ?: emptyList()

        val zkDocuments = deviceResponse.zkDocuments?.map {
            verifyZkDocument(it, verifyZkDocumentCallback!!)
        } ?: emptyList()

        val allDocuments = zkDocuments + plainDocuments

        return VerifyPresentationResult.SuccessIso(
            documents = allDocuments,
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyPlainDocument(
        document: Document,
        verifyPlainDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): IsoDocumentParsed {
        require(document.errors == null) { "Errors: ${document.errors}" }
        val issuerSigned = document.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val certificateHead = issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull()
            ?: throw IllegalArgumentException("No issuer certificate in header")
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateHead).getOrElse {
            throw IllegalArgumentException("Could not parse issuer certificate from header", it)
        }
        val issuerKey = x509Certificate.decodedPublicKey.getOrThrow().toCoseKey().getOrElse {
            throw IllegalArgumentException("Could not parse key from certificate", it)
        }

        verifyCoseSignatureWithKey(issuerAuth, issuerKey, byteArrayOf(), null).onFailure {
            throw IllegalArgumentException("IssuerAuth not verified", it)
        }

        val mso: MobileSecurityObject? = issuerSigned.issuerAuth.payload
        require(mso != null) { "mso is null" }
        require(mso.docType == document.docType) {
            "mso.docType '${mso.docType}' does not match Doc docType '${document.docType}'"
        }
        require(verifyPlainDocumentCallback.invoke(mso, document)) {
            "document callback failed: $document"
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
        return IsoPlainDocumentParsed(
            document = document,
            mso = mso,
            validItems = validItems,
            invalidItems = invalidItems,
            freshnessSummary = validator.checkCredentialFreshness(issuerSigned),
        )
    }

    /**
     * Validates an ISO ZkDocument, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyZkDocument(
        zkDocument: ZkDocument,
        verifyZkDocumentCallback: suspend ((ZkDocument) -> Boolean)
    ): IsoZkDocumentParsed {
        val allItems = zkDocument.zkDocumentDataBytes.value.issuerSigned
            ?.values
            ?.flatMap { it.entries }
            ?: emptyList()

        // All-or-nothing approach due to the zk proof approach
        val (validItems, invalidItems) = if (verifyZkDocumentCallback.invoke(zkDocument)) {
            allItems to emptyList()
        } else {
            emptyList<ZkSignedItem>() to allItems
        }

        return IsoZkDocumentParsed(
            zkDocument = zkDocument,
            validItems = validItems,
            invalidItems = invalidItems,
            // TODO: Review freshness Summary for zk documents, especially considering revocation.
            freshnessSummary = CredentialFreshnessSummary.Mdoc(
                timelinessValidationSummary = CredentialTimelinessValidationSummary.Mdoc(
                    details = MdocTimelinessValidationDetails(
                        evaluationTime = zkDocument.zkDocumentDataBytes.value.timestamp,
                        msoTimelinessValidationSummary = null,
                    )
                ),
                tokenStatusValidationResult = TokenStatusValidationResult.Valid(null)
            ),
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
        // TODO Only true in AgentIsoMdocTest when we are not deserializing the ByteStringWrappe in the issuerSignedItems
        val inputToVerifierHash = if (serialized.encodeToString(Base16Strict).uppercase().startsWith("D818"))
            serialized
        else coseCompliantSerializer
            .encodeToByteArray(ByteArraySerializer(), serialized)
            .wrapInCborTag(24)
        val verifierHash = inputToVerifierHash.sha256()
        return verifierHash.contentEquals(issuerHash.value)
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    suspend fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        val mdocInputValidator = mdocInputValidator(it, issuerKey)
        if (!mdocInputValidator.isSuccess) {
            return VerifyCredentialResult.ValidationError(
                cause = mdocInputValidator.error ?: IllegalArgumentException("No details available")
            )
        }
        return SuccessIso(it)
    }
}
