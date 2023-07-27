package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.KmmBitSet
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.RevocationListSubject
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.DOC_TYPE_MDL
import at.asitplus.wallet.lib.iso.IsoDataModelConstants.NAMESPACE_MDL
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.ValueDigestList
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.iso.wrapInCborTag
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.JwsSigned
import at.asitplus.wallet.lib.jws.VerifierJwsService
import at.asitplus.wallet.lib.toBitSet
import io.github.aakira.napier.Napier
import io.matthewnelson.component.base64.decodeBase64ToArray
import io.matthewnelson.component.encoding.base16.encodeBase16
import kotlinx.serialization.cbor.ByteStringWrapper


/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class Validator(
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(DefaultVerifierCryptoService()),
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(DefaultVerifierCryptoService()),
    private val parser: Parser = Parser(),
    private val zlibService: ZlibService = DefaultZlibService(),
) {

    companion object {
        fun newDefaultInstance(
            cryptoService: VerifierCryptoService,
            parser: Parser = Parser()
        ) = Validator(
            verifierJwsService = DefaultVerifierJwsService(cryptoService = cryptoService),
            verifierCoseService = DefaultVerifierCoseService(cryptoService = cryptoService),
            parser = parser
        )

        /**
         * Explicitly empty argument list to use it in Swift
         */
        fun newDefaultInstance() = Validator()
    }

    private var revocationList: KmmBitSet? = null

    /**
     * Sets the revocation list for verifying the revocation status of the VC
     * that will be later verified with [verifyVcJws].
     *
     * @return `true` if the revocation list was valid and has been set
     */
    fun setRevocationList(it: String): Boolean {
        Napier.d("setRevocationList: Loading $it")
        val jws = JwsSigned.parse(it)
            ?: return false
                .also { Napier.w("Revocation List: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, it))
            return false
                .also { Napier.w("Revocation List: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId
        val vcJws = VerifiableCredentialJws.deserialize(payload)
            ?: return false
                .also { Napier.w("Revocation List: Could not parse payload") }
        val parsedVc = parser.parseVcJws(it, vcJws, kid)
        if (parsedVc !is Parser.ParseVcResult.Success)
            return false
                .also { Napier.d("Revocation List: Could not parse VC: $parsedVc") }
        if (parsedVc.jws.vc.credentialSubject !is RevocationListSubject)
            return false
                .also { Napier.d("credentialSubject invalid") }
        val encodedList = parsedVc.jws.vc.credentialSubject.encodedList
        this.revocationList = encodedList.decodeBase64ToArray()?.let {
            zlibService.decompress(it)?.toBitSet() ?: return false.also { Napier.d("Invalid ZLIB") }
        } ?: return false.also { Napier.d("Invalid Base64") }
        Napier.d("Revocation list is valid")
        return true
    }

    enum class RevocationStatus {
        UNKNOWN,
        REVOKED,
        VALID;
    }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     *
     * Be sure to call [setRevocationList] first, otherwise this method will return [RevocationStatus.UNKNOWN].
     */
    fun checkRevocationStatus(vcJws: VerifiableCredentialJws): RevocationStatus {
        revocationList?.let { bitSet ->
            vcJws.vc.credentialStatus?.let { status ->
                if (bitSet.length() > status.index && bitSet[status.index])
                    return RevocationStatus.REVOKED
                return RevocationStatus.VALID
            }
        }
        return RevocationStatus.UNKNOWN
    }

    /**
     * Checks the revocation status of a Verifiable Credential with defined [statusListIndex].
     *
     * Be sure to call [setRevocationList] first, otherwise this method will return [RevocationStatus.UNKNOWN].
     */
    fun checkRevocationStatus(statusListIndex: Long): RevocationStatus {
        revocationList?.let { bitSet ->
            if (bitSet.length() > statusListIndex && bitSet[statusListIndex])
                return RevocationStatus.REVOKED
            return RevocationStatus.VALID
        }
        return RevocationStatus.UNKNOWN
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Presentation.
     *
     * @param it JWS in compact representation
     * @param challenge Nonce that the verifier has sent to the holder
     * @param localId Local keyId of the verifier
     */
    fun verifyVpJws(
        it: String,
        challenge: String,
        localId: String
    ): Verifier.VerifyPresentationResult {
        Napier.d("Verifying VP $it")
        val jws = JwsSigned.parse(it)
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(it)
                .also { Napier.w("VP: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, it))
            return Verifier.VerifyPresentationResult.InvalidStructure(it)
                .also { Napier.w("VP: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId
        val vpJws =
            kotlin.runCatching { VerifiablePresentationJws.deserialize(payload) }.getOrNull()
                ?: return Verifier.VerifyPresentationResult.InvalidStructure(it)
                    .also { Napier.w("VP: Could not parse payload") }
        val parsedVp = parser.parseVpJws(it, vpJws, kid, challenge, localId)
        if (parsedVp !is Parser.ParseVpResult.Success) {
            return Verifier.VerifyPresentationResult.InvalidStructure(it)
                .also { Napier.d("VP: Could not parse content") }
        }
        val parsedVcList = parsedVp.jws.vp.verifiableCredential
            .map { verifyVcJws(it, null) }
        val validVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.Success>()
            .map { it.jws }
        val revokedVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.Revoked>()
            .map { it.jws }
        val invalidVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.InvalidStructure>()
            .map { it.input }
        val vp = VerifiablePresentationParsed(
            parsedVp.jws.vp.id,
            parsedVp.jws.vp.type,
            validVcList.toTypedArray(),
            revokedVcList.toTypedArray(),
            invalidVcList.toTypedArray(),
        )
        Napier.d("VP: Valid")
        return Verifier.VerifyPresentationResult.Success(vp)
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    fun verifyDocument(doc: Document, challenge: String): Verifier.VerifyPresentationResult {
        if (doc.docType != DOC_TYPE_MDL)
            return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("Invalid docType: ${doc.docType}") }
        if (doc.errors != null) {
            return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("Document has errors: ${doc.errors}") }
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth
        // TODO Get Issuer Key somewhere
        //        if (verifierCoseService.verifyCose(issuerAuth, CoseKey(CoseKeyType.EC2)).getOrNull() != true) {
        //            return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
        //                .also { Napier.w("IssuerAuth not verified: $issuerAuth") }
        //        }

        val mso = issuerSigned.getIssuerAuthPayloadAsMso()
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("MSO is null: ${issuerAuth.payload?.encodeBase16()}") }
        if (mso.docType != DOC_TYPE_MDL) {
            return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("Invalid docType in MSO: ${mso.docType}") }
        }
        val mdlItems = mso.valueDigests[NAMESPACE_MDL]
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("mdlItems are null in MSO: ${mso.valueDigests}") }

        val walletKey = mso.deviceKeyInfo.deviceKey
        val deviceSignature = doc.deviceSigned.deviceAuth.deviceSignature
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("DeviceSignature is null: ${doc.deviceSigned.deviceAuth}") }
        // TODO Does the challenge need to be included in deviceSignature somehow?

        if (verifierCoseService.verifyCose(deviceSignature, walletKey).getOrNull() != true) {
            return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("DeviceSignature not verified") }
        }

        val issuerSignedItems = issuerSigned.namespaces?.get(NAMESPACE_MDL)
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(doc.serialize().encodeBase16())
                .also { Napier.w("No issuer signed items in ${issuerSigned.namespaces}") }

        val validatedItems = issuerSignedItems.entries.associateWith { it.verify(mdlItems) }
        return Verifier.VerifyPresentationResult.SuccessIso(
            IsoDocumentParsed(
                validItems = validatedItems.filter { it.value }.map { it.key.value },
                invalidItems = validatedItems.filter { !it.value }.map { it.key.value },
            )
        )
    }

    private fun ByteStringWrapper<IssuerSignedItem>.verify(mdlItems: ValueDigestList): Boolean {
        val issuerHash = mdlItems.entries.first { it.key == value.digestId }
        // TODO analyze usages of tag wrapping
        val verifierHash = serialized.wrapInCborTag(24).sha256()
        if (!verifierHash.encodeBase16().contentEquals(issuerHash.value.encodeBase16())) {
            Napier.w("Could not verify hash of value for ${value.elementIdentifier}")
            return false
        }
        return true
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param it JWS in compact representation
     * @param localId Optionally the local keyId, to verify VC was issued to correct subject
     */
    fun verifyVcJws(it: String, localId: String?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying VC $it")
        val jws = JwsSigned.parse(it)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.w("VC: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, it))
            return Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.w("VC: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val vcJws = VerifiableCredentialJws.deserialize(payload)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.w("VC: Could not parse payload") }
        localId?.let {
            if (vcJws.subject != it)
                return Verifier.VerifyCredentialResult.InvalidStructure(it)
                    .also { Napier.d("VC: sub invalid") }
        }
        if (checkRevocationStatus(vcJws) == RevocationStatus.REVOKED)
            return Verifier.VerifyCredentialResult.Revoked(it, vcJws)
                .also { Napier.d("VC: revoked") }
        val kid = jws.header.keyId
        return when (parser.parseVcJws(it, vcJws, kid)) {
            is Parser.ParseVcResult.InvalidStructure -> Verifier.VerifyCredentialResult.InvalidStructure(it)
                .also { Napier.d("VC: Invalid structure from Parser") }

            is Parser.ParseVcResult.Success -> Verifier.VerifyCredentialResult.Success(vcJws)
                .also { Napier.d("VC: Valid") }
        }
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey): Verifier.VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        val result = verifierCoseService.verifyCose(it.issuerAuth, issuerKey)
        // TODO How to get the correct issuer key!?
        //if (result.getOrNull() != true) {
        //    Napier.w("ISO: Could not verify credential", result.exceptionOrNull())
        //    return Verifier.VerifyCredentialResult.InvalidStructure(it.serialize().encodeBase16())
        //}
        return Verifier.VerifyCredentialResult.SuccessIso(it)
    }

}
