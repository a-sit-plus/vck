package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.KmmBitSet
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.CoseKey
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.Base64Strict
import at.asitplus.wallet.lib.data.Base64UrlStrict
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.RevocationListSubject
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
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
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.cbor.ByteStringWrapper
import okio.ByteString.Companion.toByteString


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
        this.revocationList = encodedList.decodeToByteArrayOrNull(Base64Strict)?.let {
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
     * @param input JWS in compact representation
     * @param challenge Nonce that the verifier has sent to the holder
     * @param localId Local keyId of the verifier
     */
    fun verifyVpJws(
        input: String,
        challenge: String,
        localId: String
    ): Verifier.VerifyPresentationResult {
        Napier.d("Verifying VP $input")
        val jws = JwsSigned.parse(input)
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("VP: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, input))
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("VP: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId
        val vpJws =
            kotlin.runCatching { VerifiablePresentationJws.deserialize(payload) }.getOrNull()
                ?: return Verifier.VerifyPresentationResult.InvalidStructure(input)
                    .also { Napier.w("VP: Could not parse payload") }
        val parsedVp = parser.parseVpJws(input, vpJws, kid, challenge, localId)
        if (parsedVp !is Parser.ParseVpResult.Success) {
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.d("VP: Could not parse content") }
        }
        val parsedVcList = parsedVp.jws.vp.verifiableCredential
            .map { verifyVcJws(it, null) }
        val validVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.SuccessJwt>()
            .map { it.jws }
        val revokedVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.Revoked>()
            .map { it.jws }
        val invalidVcList = parsedVcList
            .filterIsInstance<Verifier.VerifyCredentialResult.InvalidStructure>()
            .map { it.input }
        val vp = VerifiablePresentationParsed(
            id = parsedVp.jws.vp.id,
            type = parsedVp.jws.vp.type,
            verifiableCredentials = validVcList.toTypedArray(),
            revokedVerifiableCredentials = revokedVcList.toTypedArray(),
            invalidVerifiableCredentials = invalidVcList.toTypedArray(),
        )
        Napier.d("VP: Valid")
        return Verifier.VerifyPresentationResult.Success(vp)
    }

    fun verifyVpSdJwt(
        input: String,
        challenge: String,
        localId: String
    ): Verifier.VerifyPresentationResult {
        Napier.d("verifyVpSdJwt: '$input', '$challenge', '$localId'")
        val sdJwtResult = verifySdJwt(input, null)
        if (sdJwtResult !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Could not verify SD-JWT: $sdJwtResult") }
        }
        val jwsKeyBindingParsed = JwsSigned.parse(input.substringAfterLast("~"))
            ?: return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
                .also { Napier.w("verifyVpSdJwt: No key binding JWT") }
        val keyBinding = KeyBindingJws.deserialize(jwsKeyBindingParsed.payload.decodeToString())
            ?: return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
                .also { Napier.w("verifyVpSdJwt: No key binding JWT") }

        if (keyBinding.challenge != challenge)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}") }
        if (keyBinding.audience != localId)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}") }
        if (jwsKeyBindingParsed.header.keyId != sdJwtResult.sdJwt.subject)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Key Binding does not prove possession of subject key: ${jwsKeyBindingParsed.header.keyId}") }
        // TODO Time Validity check

        Napier.d("verifyVpSdJwt: Valid")
        return Verifier.VerifyPresentationResult.SuccessSdJwt(
            sdJwtResult.sdJwt,
            sdJwtResult.disclosures.values.filterNotNull()
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    fun verifyDocument(doc: Document, challenge: String): Verifier.VerifyPresentationResult {
        val docSerialized = doc.serialize().encodeToString(Base16(strict = true))
        if (doc.docType != DOC_TYPE_MDL)
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("Invalid docType: ${doc.docType}") }
        if (doc.errors != null) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("Document has errors: ${doc.errors}") }
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val issuerKey = issuerAuth.unprotectedHeader?.certificateChain?.let {
            CryptoUtils.extractPublicKeyFromX509Cert(it)?.toCoseKey()
        } ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
            .also { Napier.w("Got no issuer key in $issuerAuth") }

        if (verifierCoseService.verifyCose(issuerAuth, issuerKey).getOrNull() != true) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("IssuerAuth not verified: $issuerAuth") }
        }

        val mso = issuerSigned.getIssuerAuthPayloadAsMso()
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("MSO is null: ${issuerAuth.payload?.encodeToString(Base16(strict = true))}") }
        if (mso.docType != DOC_TYPE_MDL) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("Invalid docType in MSO: ${mso.docType}") }
        }
        val mdlItems = mso.valueDigests[NAMESPACE_MDL]
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("mdlItems are null in MSO: ${mso.valueDigests}") }

        val walletKey = mso.deviceKeyInfo.deviceKey
        val deviceSignature = doc.deviceSigned.deviceAuth.deviceSignature
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("DeviceSignature is null: ${doc.deviceSigned.deviceAuth}") }

        if (verifierCoseService.verifyCose(deviceSignature, walletKey).getOrNull() != true) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("DeviceSignature not verified") }
        }

        val deviceSignaturePayload = deviceSignature.payload
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("DeviceSignature does not contain challenge") }
        if (!deviceSignaturePayload.contentEquals(challenge.encodeToByteArray())) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("DeviceSignature does not contain correct challenge") }
        }

        val issuerSignedItems = issuerSigned.namespaces?.get(NAMESPACE_MDL)
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
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
        if (!verifierHash.encodeToString(Base16(strict = true))
                .contentEquals(issuerHash.value.encodeToString(Base16(strict = true)))
        ) {
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
        Napier.d("Verifying VC-JWS $it")
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

            is Parser.ParseVcResult.Success -> Verifier.VerifyCredentialResult.SuccessJwt(vcJws)
                .also { Napier.d("VC: Valid") }

            is Parser.ParseVcResult.SuccessSdJwt -> Verifier.VerifyCredentialResult.SuccessJwt(vcJws)
                .also { Napier.d("VC: Valid") }
        }
    }

    /**
     * Validates the content of a SD-JWT, expected to contain a Verifiable Credential.
     *
     * @param input SD-JWT in compact representation, i.e. `$jws~$disclosure1~$disclosure2...`
     * @param localId Optionally the local keyId, to verify VC was issued to correct subject
     */
    fun verifySdJwt(input: String, localId: String?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $input")
        val jwsSerialized = input.substringBefore("~")
        val jws = JwsSigned.parse(jwsSerialized)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws, input))
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(payload)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Could not parse payload") }
        localId?.let {
            if (sdJwt.subject != it)
                return Verifier.VerifyCredentialResult.InvalidStructure(it)
                    .also { Napier.d("verifySdJwt: sub invalid") }
        }
        val rawDisclosures = input.substringAfter("~").split("~").filterNot { it.contains(".") }
        val disclosures = rawDisclosures.associateWith {
            SelectiveDisclosureItem.deserialize(it.decodeToByteArray(Base64UrlStrict).decodeToString())
        }.filterValues { it != null }
        // it's important to read again from source string to prevent different formats in serialization
        val disclosureInputs = rawDisclosures
            .map { it.encodeToByteArray().toByteString().sha256().base64Url() }
        disclosureInputs.forEach {
            if (!sdJwt.disclosureDigests.contains(it)) {
                return Verifier.VerifyCredentialResult.InvalidStructure(input)
                    .also { Napier.w("verifySdJwt: Digest of disclosure not contained in SD-JWT: $it") }
            }
        }
        // TODO Revocation Check
        //        if (checkRevocationStatus(sdJwt) == RevocationStatus.REVOKED)
        //            return Verifier.VerifyCredentialResult.Revoked(it, sdJwt)
        //                .also { Napier.d("VC: revoked") }
        val kid = jws.header.keyId
        return when (parser.parseSdJwt(input, sdJwt, kid)) {
            is Parser.ParseVcResult.InvalidStructure -> Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.d("verifySdJwt: Invalid structure from Parser") }

            is Parser.ParseVcResult.Success -> Verifier.VerifyCredentialResult.SuccessSdJwt(sdJwt, disclosures)
                .also { Napier.d("verifySdJwt: Valid") }

            is Parser.ParseVcResult.SuccessSdJwt -> Verifier.VerifyCredentialResult.SuccessSdJwt(sdJwt, disclosures)
                .also { Napier.d("verifySdJwt: Valid") }
        }
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        if (issuerKey == null) {
            Napier.w("ISO: No issuer key")
            return Verifier.VerifyCredentialResult.InvalidStructure(
                it.serialize().encodeToString(Base16(strict = true))
            )
        }
        val result = verifierCoseService.verifyCose(it.issuerAuth, issuerKey)
        if (result.getOrNull() != true) {
            Napier.w("ISO: Could not verify credential", result.exceptionOrNull())
            return Verifier.VerifyCredentialResult.InvalidStructure(
                it.serialize().encodeToString(Base16(strict = true))
            )
        }
        return Verifier.VerifyCredentialResult.SuccessIso(it)
    }

}
