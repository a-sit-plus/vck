package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.asn1.BitSet
import at.asitplus.signum.indispensable.asn1.toBitSet
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.VerifierJwsService
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArrayOrNull
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.buildJsonObject


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

    constructor(
        cryptoService: VerifierCryptoService,
        parser: Parser = Parser(),
        zlibService: ZlibService = DefaultZlibService(),
    ) : this(
        verifierJwsService = DefaultVerifierJwsService(cryptoService = cryptoService),
        verifierCoseService = DefaultVerifierCoseService(cryptoService = cryptoService),
        parser = parser,
        zlibService = zlibService
    )

    private var revocationList: BitSet? = null

    /**
     * Sets the revocation list for verifying the revocation status of the VC
     * that will be later verified with [verifyVcJws].
     *
     * @return `true` if the revocation list was valid and has been set
     */
    fun setRevocationList(it: String): Boolean {
        Napier.d("setRevocationList: Loading $it")
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(it, vckJsonSerializer).getOrElse {
            Napier.w("Revocation List: Could not parse JWS", it)
            return false
        }
        if (!verifierJwsService.verifyJwsObject(jws)) {
            Napier.w("Revocation List: Signature invalid")
            return false
        }
        val parsedVc = parser.parseVcJws(it, jws.payload)
        if (parsedVc !is Parser.ParseVcResult.Success) {
            Napier.d("Revocation List: Could not parse VC: $parsedVc")
            return false
        }
        if (parsedVc.jws.vc.credentialSubject !is RevocationListSubject) {
            Napier.d("credentialSubject invalid")
            return false
        }
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
     * @param clientId Identifier of the verifier (i.e. the audience of the presentation)
     */
    @Throws(IllegalArgumentException::class)
    fun verifyVpJws(
        input: String,
        challenge: String,
        clientId: String
    ): Verifier.VerifyPresentationResult {
        Napier.d("Verifying VP $input")
        val jws = JwsSigned.deserialize<VerifiablePresentationJws>(input, vckJsonSerializer).getOrElse {
            Napier.w("VP: Could not parse JWS", it)
            throw IllegalArgumentException(it)
        }
        if (!verifierJwsService.verifyJwsObject(jws)) {
            Napier.w("VP: Signature invalid")
            throw IllegalArgumentException("signature")
        }
        val parsedVp = parser.parseVpJws(input, jws.payload, challenge, clientId)
        if (parsedVp !is Parser.ParseVpResult.Success) {
            Napier.d("VP: Could not parse content")
            throw IllegalArgumentException("vp.content")
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

    /**
     * Validates the content of a SD-JWT presentation, expected to contain a [VerifiableCredentialSdJwt],
     * as well as some disclosures and a key binding JWT at the end.
     *
     * @param input SD-JWT in compact representation, i.e. `$jws~$disclosure1~$disclosure2...~$keyBinding`
     * @param clientId Identifier of the verifier, to verify audience of key binding JWS
     */
    fun verifyVpSdJwt(
        input: String,
        challenge: String,
        clientId: String
    ): Verifier.VerifyPresentationResult {
        Napier.d("verifyVpSdJwt: '$input', '$challenge', '$clientId'")
        val sdJwtResult = verifySdJwt(input, null)
        if (sdJwtResult !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
            Napier.w("verifyVpSdJwt: Could not verify SD-JWT: $sdJwtResult")
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
        }
        val keyBindingSigned = sdJwtResult.sdJwtSigned.keyBindingJws ?: run {
            Napier.w("verifyVpSdJwt: No key binding JWT")
            return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
        }
        if (!verifierJwsService.verifyJwsObject(keyBindingSigned)) {
            Napier.w("verifyVpSdJwt: Key binding JWT not verified")
            return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
        }
        val keyBinding = keyBindingSigned.payload

        if (keyBinding.challenge != challenge) {
            Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}, expected $clientId")
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
        }
        if (keyBinding.audience != clientId) {
            Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}, expected $clientId")
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
        }
        val vcSdJwt = sdJwtResult.verifiableCredentialSdJwt
        if (!vcSdJwt.verifyKeyBinding(keyBindingSigned.header, keyBindingSigned)) {
            Napier.w("verifyVpSdJwt: Key Binding $keyBindingSigned does not prove possession of subject")
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
        }

        val hashInput = input.substringBeforeLast("~") + "~"
        if (!keyBinding.sdHash.contentEquals(hashInput.encodeToByteArray().sha256())) {
            Napier.w("verifyVpSdJwt: Key Binding does not contain correct sd_hash")
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
        }

        Napier.d("verifyVpSdJwt: Valid")
        return Verifier.VerifyPresentationResult.SuccessSdJwt(
            sdJwtSigned = sdJwtResult.sdJwtSigned,
            verifiableCredentialSdJwt = vcSdJwt,
            reconstructedJsonObject = sdJwtResult.reconstructedJsonObject,
            disclosures = sdJwtResult.disclosures.values,
            isRevoked = sdJwtResult.isRevoked,
        )
    }

    private fun VerifiableCredentialSdJwt.verifyKeyBinding(
        jwsHeader: JwsHeader,
        keyBindingSigned: JwsSigned<KeyBindingJws>
    ): Boolean =
        if (confirmationClaim != null) {
            verifierJwsService.verifyConfirmationClaim(this.confirmationClaim, keyBindingSigned)
        } else {
            subject == jwsHeader.keyId
        }

    /**
     * Validates an ISO device response, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class)
    fun verifyDeviceResponse(deviceResponse: DeviceResponse, challenge: String): Verifier.VerifyPresentationResult {
        if (deviceResponse.status != 0U) {
            Napier.w("Status invalid: ${deviceResponse.status}")
            throw IllegalArgumentException("status")
        }
        if (deviceResponse.documents == null) {
            Napier.w("No documents: $deviceResponse")
            throw IllegalArgumentException("documents")
        }
        return Verifier.VerifyPresentationResult.SuccessIso(
            documents = deviceResponse.documents.map { verifyDocument(it, challenge) }
        )
    }

    /**
     * Validates an ISO document, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class)
    fun verifyDocument(doc: Document, challenge: String): IsoDocumentParsed {
        if (doc.errors != null) {
            Napier.w("Document has errors: ${doc.errors}")
            throw IllegalArgumentException("errors")
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val certificateChain = issuerAuth.unprotectedHeader?.certificateChain ?: run {
            Napier.w("Got no issuer certificate in $issuerAuth")
            throw IllegalArgumentException("issuerKey")
        }
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateChain).getOrElse {
            Napier.w("Could not parse issuer certificate in ${certificateChain.encodeToString(Base64())}", it)
            throw IllegalArgumentException("issuerKey")
        }
        val issuerKey = x509Certificate.publicKey.toCoseKey().getOrElse {
            Napier.w("Could not parse key from certificate in $x509Certificate", it)
            throw IllegalArgumentException("issuerKey")
        }

        if (verifierCoseService.verifyCose(issuerAuth, issuerKey).isFailure) {
            Napier.w("IssuerAuth not verified: $issuerAuth")
            throw IllegalArgumentException("issuerAuth")
        }

        val mso: MobileSecurityObject? = issuerSigned.issuerAuth.getTypedPayload(MobileSecurityObject.serializer()).onFailure {
                throw IllegalArgumentException("mso", it)
                Napier.w("MSO could not be decoded", it)
            }.getOrNull()?.value
        if (mso == null) {
            Napier.w("MSO is null: ${issuerAuth.payload?.encodeToString(Base16(strict = true))}")
            throw IllegalArgumentException("mso")
        }

        if (mso.docType != doc.docType) {
            Napier.w("Invalid MSO docType '${mso.docType}' does not match Doc docType '${doc.docType}")
            throw IllegalArgumentException("mso.docType")
        }
        val walletKey = mso.deviceKeyInfo.deviceKey
        val deviceSignature = doc.deviceSigned.deviceAuth.deviceSignature ?: run {
            Napier.w("DeviceSignature is null: ${doc.deviceSigned.deviceAuth}")
            throw IllegalArgumentException("deviceSignature")
        }

        if (verifierCoseService.verifyCose(deviceSignature, walletKey).isFailure) {
            Napier.w("DeviceSignature not verified")
            throw IllegalArgumentException("deviceSignature")
        }

        val deviceSignaturePayload = deviceSignature.payload ?: run {
            Napier.w("DeviceSignature does not contain challenge")
            throw IllegalArgumentException("challenge")
        }
        if (!deviceSignaturePayload.contentEquals(challenge.encodeToByteArray())) {
            Napier.w("DeviceSignature does not contain correct challenge")
            throw IllegalArgumentException("challenge")
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
        return IsoDocumentParsed(mso = mso, validItems = validItems, invalidItems = invalidItems)
    }

    /**
     * Verify that calculated digests equal the corresponding digest values in the MSO.
     *
     * See ISO/IEC 18013-5:2021, 9.3.1 Inspection procedure for issuer data authentication
     */
    private fun ByteStringWrapper<IssuerSignedItem>.verify(mdlItems: ValueDigestList?): Boolean {
        val issuerHash = mdlItems?.entries?.firstOrNull { it.key == value.digestId }
            ?: return false
        val verifierHash = serialized.wrapInCborTag(24).sha256()
        if (!verifierHash.contentEquals(issuerHash.value)) {
            Napier.w("Could not verify hash of value for ${value.elementIdentifier}")
            return false
        }
        return true
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally the local key, to verify VC was issued to correct subject
     */
    fun verifyVcJws(input: String, publicKey: CryptoPublicKey?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying VC-JWS $input")
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(input, vckJsonSerializer).getOrElse {
            Napier.w("VC: Could not parse JWS", it)
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }
        if (!verifierJwsService.verifyJwsObject(jws)) {
            Napier.w("VC: Signature invalid")
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }
        val vcJws = jws.payload
        publicKey?.let {
            if (!it.matchesIdentifier(vcJws.subject)) {
                Napier.d("VC: sub invalid")
                return Verifier.VerifyCredentialResult.InvalidStructure(input)
            }
        }
        if (checkRevocationStatus(vcJws) == RevocationStatus.REVOKED) {
            Napier.d("VC: revoked")
            return Verifier.VerifyCredentialResult.Revoked(input, vcJws)
        }
        return when (parser.parseVcJws(input, vcJws)) {
            is Parser.ParseVcResult.InvalidStructure -> Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.d("VC: Invalid structure from Parser") }

            is Parser.ParseVcResult.Success -> Verifier.VerifyCredentialResult.SuccessJwt(vcJws)
                .also { Napier.d("VC: Valid") }

            is Parser.ParseVcResult.SuccessSdJwt -> Verifier.VerifyCredentialResult.SuccessJwt(vcJws)
                .also { Napier.d("VC: Valid") }
        }
    }

    /**
     * Validates the content of a SD-JWT, expected to contain a [VerifiableCredentialSdJwt].
     *
     * @param input SD-JWT in compact representation, i.e. `$jws~$disclosure1~$disclosure2...`
     * @param publicKey Optionally the local key, to verify SD-JWT was issued to correct subject
     */
    fun verifySdJwt(input: String, publicKey: CryptoPublicKey?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $input for $publicKey")
        val sdJwtSigned = SdJwtSigned.parse(input) ?: run {
            Napier.w("verifySdJwt: Could not parse SD-JWT from $input")
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }
        if (!verifierJwsService.verifyJwsObject(sdJwtSigned.jws)) {
            Napier.w("verifySdJwt: Signature invalid")
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }
        val sdJwt = sdJwtSigned.getPayloadAsVerifiableCredentialSdJwt().getOrElse { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }
        if (publicKey != null && sdJwt.subject != null) {
            if (!publicKey.matchesIdentifier(sdJwt.subject)) {
                Napier.d("verifySdJwt: sub invalid")
                return Verifier.VerifyCredentialResult.InvalidStructure(input)
            }
        }
        val isRevoked = checkRevocationStatus(sdJwt) == RevocationStatus.REVOKED
        if (isRevoked)
            Napier.d("verifySdJwt: revoked")
        val issuerSigned = sdJwtSigned.getPayloadAsJsonObject().getOrElse { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }

        val sdJwtValidator = SdJwtValidator(sdJwtSigned)
        val reconstructedJsonObject = sdJwtValidator.reconstructedJsonObject
            ?: buildJsonObject { }

        /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
        val validDisclosures: Map<String, SelectiveDisclosureItem> = sdJwtValidator.validDisclosures
        return when (parser.parseSdJwt(input, sdJwt)) {
            is Parser.ParseVcResult.SuccessSdJwt -> {
                Verifier.VerifyCredentialResult.SuccessSdJwt(
                    sdJwtSigned = sdJwtSigned,
                    verifiableCredentialSdJwt = sdJwt,
                    reconstructedJsonObject = reconstructedJsonObject,
                    disclosures = validDisclosures,
                    isRevoked = isRevoked
                ).also { Napier.d("verifySdJwt: Valid") }
            }

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
        if (result.isFailure) {
            Napier.w("ISO: Could not verify credential", result.exceptionOrNull())
            return Verifier.VerifyCredentialResult.InvalidStructure(
                it.serialize().encodeToString(Base16(strict = true))
            )
        }
        return Verifier.VerifyCredentialResult.SuccessIso(it)
    }

}
