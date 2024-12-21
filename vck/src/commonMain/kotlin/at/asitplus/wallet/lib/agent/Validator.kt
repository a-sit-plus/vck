package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.JwsHeader
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.cbor.DefaultVerifierCoseService
import at.asitplus.wallet.lib.cbor.VerifierCoseService
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.Status
import at.asitplus.wallet.lib.data.StatusListToken
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.data.vckJsonSerializer
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.iso.ValueDigestList
import at.asitplus.wallet.lib.iso.sha256
import at.asitplus.wallet.lib.iso.wrapInCborTag
import at.asitplus.wallet.lib.jws.DefaultVerifierJwsService
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.VerifierJwsService
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.json.buildJsonObject
import kotlin.coroutines.cancellation.CancellationException

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class Validator(
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(
        DefaultVerifierCryptoService(),
    ),
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(
        DefaultVerifierCryptoService(),
    ),
    private val parser: Parser = Parser(),
    /**
     * This function should check the status mechanisms in a given status claim in order to
     * evaluate the token status.
     * If [tokenStatusResolver] is null, all tokens are considered to be valid.
     */
    private val tokenStatusResolver: (suspend (Status) -> TokenStatus)? = null,
) {
    constructor(
        cryptoService: VerifierCryptoService,
        parser: Parser = Parser(),
        tokenStatusResolver: (suspend (Status) -> TokenStatus)? = null,
    ) : this(
        verifierJwsService = DefaultVerifierJwsService(cryptoService = cryptoService),
        verifierCoseService = DefaultVerifierCoseService(cryptoService = cryptoService),
        parser = parser,
        tokenStatusResolver = tokenStatusResolver,
    )

    constructor(
        resolveStatusListToken: suspend (UniformResourceIdentifier) -> StatusListToken,
        verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(
            DefaultVerifierCryptoService(),
        ),
        verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(
            DefaultVerifierCryptoService(),
        ),
        parser: Parser = Parser(),
        zlibService: ZlibService = DefaultZlibService(),
        clock: Clock = Clock.System,
    ) : this(
        verifierJwsService = verifierJwsService,
        verifierCoseService = verifierCoseService,
        parser = parser,
        tokenStatusResolver = { status ->
            val token = resolveStatusListToken(status.statusList.uri)

            val payload = token.validate(
                verifierJwsService = verifierJwsService,
                verifierCoseService = verifierCoseService,
                statusListInfo = status.statusList,
                isInstantInThePast = {
                    it < clock.now()
                },
            ).getOrThrow()

            StatusListTokenValidator.extractTokenStatus(
                statusList = payload.statusList,
                statusListInfo = status.statusList,
                zlibService = zlibService,
            ).getOrThrow()
        },
    )

    /**
     * Checks the revocation state of the passed MDOC Credential.
     */
    suspend fun checkRevocationStatus(issuerSigned: IssuerSigned): TokenStatus? {
        return issuerSigned.issuerAuth.payload?.status?.let {
            checkRevocationStatus(it)
        }
    }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     */
    suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws): TokenStatus? {
        return vcJws.vc.credentialStatus?.let {
            checkRevocationStatus(it)
        }
    }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     */
    suspend fun checkRevocationStatus(sdJwt: VerifiableCredentialSdJwt): TokenStatus? {
        return sdJwt.credentialStatus?.let {
            checkRevocationStatus(it)
        }
    }

    /**
     * Checks the revocation state using the provided status mechanisms
     */
    private suspend fun checkRevocationStatus(status: Status): TokenStatus {
        val resolver = tokenStatusResolver ?: {
            TokenStatus.Valid
        }
        return try {
            resolver.invoke(status)
        } catch (_: Throwable) {
            // A status mechanism is specified, but no status can be retrieved, consider this to be
            // invalid
            TokenStatus.Invalid
        }
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Presentation.
     *
     * @param input JWS in compact representation
     * @param challenge Nonce that the verifier has sent to the holder
     * @param clientId Identifier of the verifier (i.e. the audience of the presentation)
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyVpJws(
        input: String,
        challenge: String,
        clientId: String,
    ): Verifier.VerifyPresentationResult {
        Napier.d("Verifying VP $input")
        val jws = JwsSigned.deserialize<VerifiablePresentationJws>(
            VerifiablePresentationJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
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
    suspend fun verifyVpSdJwt(
        input: String,
        challenge: String,
        clientId: String,
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
        keyBindingSigned: JwsSigned<KeyBindingJws>,
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
    fun verifyDeviceResponse(
        deviceResponse: DeviceResponse,
        challenge: String
    ): Verifier.VerifyPresentationResult {
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
            Napier.w(
                "Could not parse issuer certificate in ${certificateChain.encodeToString(Base64())}",
                it
            )
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

        val mso: MobileSecurityObject? = issuerSigned.issuerAuth.payload
        if (mso == null) {
            Napier.w("MSO is null: $issuerAuth")
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
            Napier.w("DeviceSignature not verified: ${doc.deviceSigned.deviceAuth}")
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
    suspend fun verifyVcJws(
        input: String,
        publicKey: CryptoPublicKey?
    ): Verifier.VerifyCredentialResult {
        Napier.d("Verifying VC-JWS $input")
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
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
        vcJws.vc.credentialStatus?.let {
            Napier.d("VC: status found")
            if (checkRevocationStatus(it) == TokenStatus.Invalid) {
                Napier.d("VC: revoked")
                return Verifier.VerifyCredentialResult.Revoked(input, vcJws)
            }
            Napier.d("VC: not revoked")
        }
        return when (parser.parseVcJws(input, vcJws)) {
            is Parser.ParseVcResult.InvalidStructure -> {
                Verifier.VerifyCredentialResult.InvalidStructure(input)
                    .also { Napier.d("VC: Invalid structure from Parser") }
            }

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
    suspend fun verifySdJwt(
        input: String,
        publicKey: CryptoPublicKey?,
    ): Verifier.VerifyCredentialResult {
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
        val isRevoked = checkRevocationStatus(sdJwt) == TokenStatus.Invalid
        if (isRevoked) {
            Napier.d("verifySdJwt: revoked")
        }
        val issuerSigned = sdJwtSigned.getPayloadAsJsonObject().getOrElse { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
            return Verifier.VerifyCredentialResult.InvalidStructure(input)
        }

        val sdJwtValidator = SdJwtValidator(sdJwtSigned)
        val reconstructedJsonObject = sdJwtValidator.reconstructedJsonObject ?: buildJsonObject { }

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
