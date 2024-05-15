package at.asitplus.wallet.lib.agent

import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import at.asitplus.crypto.datatypes.io.BitSet
import at.asitplus.crypto.datatypes.io.toBitSet
import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.RevocationListSubject
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.ValueDigestList
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.iso.wrapInCborTag
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.VerifierJwsService
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

    private var revocationList: BitSet? = null

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
        if (!verifierJwsService.verifyJwsObject(jws))
            return false
                .also { Napier.w("Revocation List: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId
        val vcJws = VerifiableCredentialJws.deserialize(payload).getOrElse { ex ->
            return false
                .also { Napier.w("Revocation List: Could not parse payload", ex) }
        }
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
        /**
         * Either no revocation status list has been set (see [Validator.setRevocationList]),
         * or there is no revocation lookup information attached to the credential.
         */
        UNKNOWN,

        /**
         * Revocation status list is available, credential has been marked revoked in there.
         */
        REVOKED,

        /**
         * Revocation status list is available, credential is not revoked.
         */
        VALID;
    }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     *
     * Be sure to call [setRevocationList] first, otherwise this method will return [RevocationStatus.UNKNOWN].
     */
    fun checkRevocationStatus(vcJws: VerifiableCredentialJws): RevocationStatus {
        return vcJws.vc.credentialStatus?.index?.let { checkRevocationStatus(it) } ?: RevocationStatus.UNKNOWN
    }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     *
     * Be sure to call [setRevocationList] first, otherwise this method will return [RevocationStatus.UNKNOWN].
     */
    fun checkRevocationStatus(sdJwt: VerifiableCredentialSdJwt): RevocationStatus {
        return sdJwt.credentialStatus?.index?.let { checkRevocationStatus(it) } ?: RevocationStatus.UNKNOWN
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
        if (!verifierJwsService.verifyJwsObject(jws))
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("VP: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val kid = jws.header.keyId
        val vpJws = VerifiablePresentationJws.deserialize(payload).getOrElse { ex ->
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("VP: Could not parse payload", ex) }
        }
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
            verifiableCredentials = validVcList,
            revokedVerifiableCredentials = revokedVcList,
            invalidVerifiableCredentials = invalidVcList,
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
        val keyBinding = KeyBindingJws.deserialize(jwsKeyBindingParsed.payload.decodeToString()).getOrElse { ex ->
            return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
                .also { Napier.w("verifyVpSdJwt: No key binding JWT", ex) }
        }

        if (keyBinding.challenge != challenge)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}") }
        if (keyBinding.audience != localId)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}") }
        if (jwsKeyBindingParsed.header.keyId != sdJwtResult.sdJwt.subject)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Key Binding does not prove possession of subject key: ${jwsKeyBindingParsed.header.keyId}") }

        Napier.d("verifyVpSdJwt: Valid")
        return Verifier.VerifyPresentationResult.SuccessSdJwt(
            sdJwt = sdJwtResult.sdJwt,
            disclosures = sdJwtResult.disclosures.values.filterNotNull(),
            isRevoked = sdJwtResult.isRevoked,
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    fun verifyDocument(doc: Document, challenge: String): Verifier.VerifyPresentationResult {
        val docSerialized = doc.serialize().encodeToString(Base16(strict = true))
        if (doc.errors != null) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("Document has errors: ${doc.errors}") }
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val issuerKey = issuerAuth.unprotectedHeader?.certificateChain?.let {
            X509Certificate.decodeFromDerOrNull(it)?.publicKey?.toCoseKey()?.getOrNull()
        } ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
            .also { Napier.w("Got no issuer key in $issuerAuth") }

        if (verifierCoseService.verifyCose(issuerAuth, issuerKey).getOrNull() != true) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("IssuerAuth not verified: $issuerAuth") }
        }

        val mso = issuerSigned.getIssuerAuthPayloadAsMso()
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("MSO is null: ${issuerAuth.payload?.encodeToString(Base16(strict = true))}") }
        if (mso.docType != doc.docType) {
            return Verifier.VerifyPresentationResult.InvalidStructure(docSerialized)
                .also { Napier.w("Invalid MSO docType '${mso.docType}' does not match Doc docType '${doc.docType}") }
        }
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
        return Verifier.VerifyPresentationResult.SuccessIso(
            IsoDocumentParsed(validItems = validItems, invalidItems = invalidItems)
        )
    }

    private fun ByteStringWrapper<IssuerSignedItem>.verify(mdlItems: ValueDigestList?): Boolean {
        val issuerHash = mdlItems?.entries?.firstOrNull { it.key == value.digestId } ?: return false
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
     * @param input JWS in compact representation
     * @param localId Optionally the local keyId, to verify VC was issued to correct subject
     */
    fun verifyVcJws(input: String, localId: String?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying VC-JWS $input")
        val jws = JwsSigned.parse(input)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("VC: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws))
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("VC: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val vcJws = VerifiableCredentialJws.deserialize(payload).getOrElse { ex ->
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("VC: Could not parse payload", ex) }
        }
        localId?.let {
            if (vcJws.subject != it)
                return Verifier.VerifyCredentialResult.InvalidStructure(it)
                    .also { Napier.d("VC: sub invalid") }
        }
        if (checkRevocationStatus(vcJws) == RevocationStatus.REVOKED)
            return Verifier.VerifyCredentialResult.Revoked(input, vcJws)
                .also { Napier.d("VC: revoked") }
        val kid = jws.header.keyId
        return when (parser.parseVcJws(input, vcJws, kid)) {
            is Parser.ParseVcResult.InvalidStructure -> Verifier.VerifyCredentialResult.InvalidStructure(input)
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
        if (!verifierJwsService.verifyJwsObject(jws))
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Signature invalid") }
        val payload = jws.payload.decodeToString()
        val sdJwt = VerifiableCredentialSdJwt.deserialize(payload).getOrElse { ex ->
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Could not parse payload", ex) }
        }
        localId?.let {
            if (sdJwt.subject != it)
                return Verifier.VerifyCredentialResult.InvalidStructure(it)
                    .also { Napier.d("verifySdJwt: sub invalid") }
        }
        val isRevoked = checkRevocationStatus(sdJwt) == RevocationStatus.REVOKED
        if (isRevoked)
            Napier.d("verifySdJwt: revoked")
        val rawDisclosures = input.substringAfter("~").split("~").filterNot { it.contains(".") }
        val disclosures = rawDisclosures.associateWith {
            SelectiveDisclosureItem.deserialize(it.decodeToByteArray(Base64UrlStrict).decodeToString()).getOrNull()
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
        val kid = jws.header.keyId
        return when (parser.parseSdJwt(input, sdJwt, kid)) {
            is Parser.ParseVcResult.SuccessSdJwt ->
                Verifier.VerifyCredentialResult.SuccessSdJwt(sdJwt, disclosures, isRevoked)
                    .also { Napier.d("verifySdJwt: Valid") }

            else -> Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.d("verifySdJwt: Invalid structure from Parser") }
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
