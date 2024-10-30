package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.BitSet
import at.asitplus.signum.indispensable.io.toBitSet
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
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(it, vckJsonSerializer).getOrNull()
            ?: return false
                .also { Napier.w("Revocation List: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws))
            return false
                .also { Napier.w("Revocation List: Signature invalid") }
        val kid = jws.header.keyId
        val parsedVc = parser.parseVcJws(it, jws.payload, kid)
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
     * @param publicKey Local key of the verifier
     */
    fun verifyVpJws(
        input: String,
        challenge: String,
        publicKey: CryptoPublicKey
    ): Verifier.VerifyPresentationResult {
        Napier.d("Verifying VP $input")
        val jws = JwsSigned.deserialize<VerifiablePresentationJws>(input, vckJsonSerializer).getOrNull()
            ?: return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("VP: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws))
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("VP: Signature invalid") }
        val kid = jws.header.keyId
        val parsedVp = parser.parseVpJws(input, jws.payload, kid, challenge, publicKey)
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

    /**
     * Validates the content of a SD-JWT presentation, expected to contain a [VerifiableCredentialSdJwt],
     * as well as some disclosures and a key binding JWT at the end.
     *
     * @param input SD-JWT in compact representation, i.e. `$jws~$disclosure1~$disclosure2...~$keyBinding`
     * @param publicKey Local key of the verifier, to verify audience of key binding JWS
     */
    fun verifyVpSdJwt(
        input: String,
        challenge: String,
        publicKey: CryptoPublicKey
    ): Verifier.VerifyPresentationResult {
        Napier.d("verifyVpSdJwt: '$input', '$challenge', '$publicKey'")
        val sdJwtResult = verifySdJwt(input, null)
        if (sdJwtResult !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Could not verify SD-JWT: $sdJwtResult") }
        }
        val keyBindingSigned = sdJwtResult.sdJwtSigned.keyBindingJws
            ?: return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
                .also { Napier.w("verifyVpSdJwt: No key binding JWT") }
        if (!verifierJwsService.verifyJwsObject(keyBindingSigned)) {
            return Verifier.VerifyPresentationResult.NotVerified(input, challenge)
                .also { Napier.w("verifyVpSdJwt: Key binding JWT not verified") }
        }
        val keyBinding = keyBindingSigned.payload

        if (keyBinding.challenge != challenge)
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}") }
        if (!publicKey.matchesIdentifier(keyBinding.audience))
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}") }
        val vcSdJwt = sdJwtResult.verifiableCredentialSdJwt
        if (!vcSdJwt.verifyKeyBinding(keyBindingSigned.header, keyBindingSigned)) {
            Napier.w("verifyVpSdJwt: Key Binding $keyBindingSigned does not prove possession of subject")
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
        }

        val hashInput = input.substringBeforeLast("~") + "~"
        if (!keyBinding.sdHash.contentEquals(hashInput.encodeToByteArray().sha256()))
            return Verifier.VerifyPresentationResult.InvalidStructure(input)
                .also { Napier.w("verifyVpSdJwt: Key Binding does not contain correct sd_hash") }

        Napier.d("verifyVpSdJwt: Valid")
        @Suppress("DEPRECATION")
        return Verifier.VerifyPresentationResult.SuccessSdJwt(
            sdJwtSigned = sdJwtResult.sdJwtSigned,
            verifiableCredentialSdJwt = vcSdJwt,
            sdJwt = sdJwtResult.sdJwt,
            reconstructedJsonObject = sdJwtResult.reconstructedJsonObject,
            disclosures = sdJwtResult.disclosures.values,
            isRevoked = sdJwtResult.isRevoked,
        )
    }

    @Suppress("DEPRECATION")
    private fun VerifiableCredentialSdJwt.verifyKeyBinding(
        jwsHeader: JwsHeader,
        keyBindingSigned: JwsSigned<KeyBindingJws>
    ): Boolean =
        if (confirmationClaim != null) {
            verifierJwsService.verifyConfirmationClaim(this.confirmationClaim!!, keyBindingSigned)
        } else if (confirmationKey != null) { // "old" method before vck 5.1.0
            jwsHeader.jsonWebKey?.let {
                confirmationKey!!.equalsCryptographically(it)
            } ?: false
        } else if (subject != jwsHeader.keyId) {
            false
        } else {
            false
        }

    /**
     * Validates an ISO device response, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class)
    fun verifyDeviceResponse(deviceResponse: DeviceResponse, challenge: String): Verifier.VerifyPresentationResult {
        if (deviceResponse.status != 0U) {
            throw IllegalArgumentException("status")
                .also { Napier.w("Status invalid: ${deviceResponse.status}") }
        }
        if (deviceResponse.documents == null) {
            throw IllegalArgumentException("documents")
                .also { Napier.w("No documents: $deviceResponse") }
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
        val docSerialized = doc.serialize().encodeToString(Base16(strict = true))
        if (doc.errors != null) {
            throw IllegalArgumentException("errors")
                .also { Napier.w("Document has errors: ${doc.errors}") }
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val issuerKey = issuerAuth.unprotectedHeader?.certificateChain?.let {
            X509Certificate.decodeFromDerOrNull(it)?.publicKey?.toCoseKey()?.getOrNull()
        } ?: throw IllegalArgumentException("issuerKey")
            .also { Napier.w("Got no issuer key in $issuerAuth") }

        if (verifierCoseService.verifyCose(issuerAuth, issuerKey).isFailure) {
            throw IllegalArgumentException("issuerAuth")
                .also { Napier.w("IssuerAuth not verified: $issuerAuth") }
        }

        val mso = issuerSigned.getIssuerAuthPayloadAsMso().getOrNull()
            ?: throw IllegalArgumentException("mso")
                .also { Napier.w("MSO is null: ${issuerAuth.payload?.encodeToString(Base16(strict = true))}") }
        if (mso.docType != doc.docType) {
            throw IllegalArgumentException("mso.docType")
                .also { Napier.w("Invalid MSO docType '${mso.docType}' does not match Doc docType '${doc.docType}") }
        }
        val walletKey = mso.deviceKeyInfo.deviceKey
        val deviceSignature = doc.deviceSigned.deviceAuth.deviceSignature
            ?: throw IllegalArgumentException("deviceSignature")
                .also { Napier.w("DeviceSignature is null: ${doc.deviceSigned.deviceAuth}") }

        if (verifierCoseService.verifyCose(deviceSignature, walletKey).isFailure) {
            throw IllegalArgumentException("deviceSignature")
                .also { Napier.w("DeviceSignature not verified") }
        }

        val deviceSignaturePayload = deviceSignature.payload
            ?: throw IllegalArgumentException("challenge")
                .also { Napier.w("DeviceSignature does not contain challenge") }
        if (!deviceSignaturePayload.contentEquals(challenge.encodeToByteArray())) {
            throw IllegalArgumentException("challenge")
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
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(input, vckJsonSerializer).getOrNull()
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("VC: Could not parse JWS") }
        if (!verifierJwsService.verifyJwsObject(jws))
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("VC: Signature invalid") }
        val vcJws = jws.payload
        publicKey?.let {
            if (!it.matchesIdentifier(vcJws.subject)) {
                return Verifier.VerifyCredentialResult.InvalidStructure(input)
                    .also { Napier.d("VC: sub invalid") }
            }
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
     * Validates the content of a SD-JWT, expected to contain a [VerifiableCredentialSdJwt].
     *
     * @param input SD-JWT in compact representation, i.e. `$jws~$disclosure1~$disclosure2...`
     * @param publicKey Optionally the local key, to verify SD-JWT was issued to correct subject
     */
    fun verifySdJwt(input: String, publicKey: CryptoPublicKey?): Verifier.VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $input for $publicKey")
        val sdJwtSigned = SdJwtSigned.parse(input)
            ?: return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Could not parse SD-JWT from $input") }
        if (!verifierJwsService.verifyJwsObject(sdJwtSigned.jws))
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Signature invalid") }
        val sdJwt = sdJwtSigned.getPayloadAsVerifiableCredentialSdJwt().getOrElse { ex ->
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Could not parse payload", ex) }
        }
        if (publicKey != null && sdJwt.subject != null) {
            if (!publicKey.matchesIdentifier(sdJwt.subject))
                return Verifier.VerifyCredentialResult.InvalidStructure(input)
                    .also { Napier.d("verifySdJwt: sub invalid") }
        }
        val isRevoked = checkRevocationStatus(sdJwt) == RevocationStatus.REVOKED
        if (isRevoked)
            Napier.d("verifySdJwt: revoked")
        val issuerSigned = sdJwtSigned.getPayloadAsJsonObject().getOrElse { ex ->
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.w("verifySdJwt: Could not parse payload", ex) }
        }

        val sdJwtValidator = SdJwtValidator(sdJwtSigned)
        val reconstructedJsonObject = sdJwtValidator.reconstructedJsonObject
            ?: buildJsonObject { }

        /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
        val validDisclosures: Map<String, SelectiveDisclosureItem> = sdJwtValidator.validDisclosures
        val kid = sdJwtSigned.jws.header.keyId
        return when (parser.parseSdJwt(input, sdJwt, kid)) {
            is Parser.ParseVcResult.SuccessSdJwt -> {
                Verifier.VerifyCredentialResult.SuccessSdJwt(
                    sdJwtSigned = sdJwtSigned,
                    verifiableCredentialSdJwt = sdJwt,
                    sdJwt = sdJwt,
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
