package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.contentEquals
import at.asitplus.openid.sha256
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.toCoseKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.toX509SignatureAlgorithm
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult.ValidationError
import at.asitplus.wallet.lib.cbor.*
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenValidator
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.json.buildJsonObject
import kotlin.coroutines.cancellation.CancellationException

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class Validator(
    @Deprecated("Use verifyJwsSignatureObject instead")
    private val verifierJwsService: VerifierJwsService = DefaultVerifierJwsService(),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(),
    @Deprecated("Use verifyCoseSignature instead")
    private val verifierCoseService: VerifierCoseService = DefaultVerifierCoseService(),
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> = VerifyCoseSignatureWithKey(),
    private val parser: Parser = Parser(),
    /**
     * This function should check the status mechanisms in a given status claim in order to
     * evaluate the token status.
     * If [tokenStatusResolver] is null, all tokens are considered to be valid.
     */
    private val tokenStatusResolver: (suspend (Status) -> TokenStatus)? = null,

    /**
     * Toggles whether transaction data should be verified if present
     */
    private val verifyTransactionData: Boolean = true,
) {
    @Deprecated("Use constructor with verifySignature")
    constructor(
        cryptoService: VerifierCryptoService,
        parser: Parser = Parser(),
        tokenStatusResolver: (suspend (Status) -> TokenStatus)? = null,
    ) : this(
        verifyJwsObject = VerifyJwsObject(VerifyJwsSignature { input, signature, algorithm, publicKey ->
            cryptoService.verify(input, signature, algorithm.toX509SignatureAlgorithm().getOrThrow(), publicKey)
        }),
        verifyCoseSignatureWithKey = VerifyCoseSignatureWithKey { input, signature, algorithm, publicKey ->
            cryptoService.verify(input, signature, algorithm.toX509SignatureAlgorithm().getOrThrow(), publicKey)
        },
        parser = parser,
        tokenStatusResolver = tokenStatusResolver,
    )

    constructor(
        verifySignature: VerifySignatureFun,
        parser: Parser = Parser(),
        tokenStatusResolver: (suspend (Status) -> TokenStatus)? = null,
    ) : this(
        verifyJwsObject = VerifyJwsObject(VerifyJwsSignature(verifySignature)),
        verifyCoseSignatureWithKey = VerifyCoseSignatureWithKey(verifySignature),
        parser = parser,
        tokenStatusResolver = tokenStatusResolver,
    )

    constructor(
        resolveStatusListToken: suspend (UniformResourceIdentifier) -> StatusListToken,
        verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(),
        verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> = VerifyCoseSignatureWithKey(),
        verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
        zlibService: ZlibService = DefaultZlibService(),
        clock: Clock = Clock.System,
        parser: Parser = Parser(clock = clock),
    ) : this(
        verifyJwsObject = verifyJwsObject,
        verifyCoseSignatureWithKey = verifyCoseSignatureWithKey,
        parser = parser,
        tokenStatusResolver = { status ->
            val token = resolveStatusListToken(status.statusList.uri)

            val payload = token.validate(
                verifyJwsObject = verifyJwsObject,
                verifyCoseSignature = verifyCoseSignature,
                statusListInfo = status.statusList,
                isInstantInThePast = {
                    it < clock.now()
                },
            ).getOrThrow()

            StatusListTokenValidator.extractTokenStatus(
                statusList = payload.statusList,
                statusListInfo = status.statusList,
            ).getOrThrow()
        },
    )

    /**
     * Checks the revocation state of the passed MDOC Credential.
     */
    suspend fun checkRevocationStatus(issuerSigned: IssuerSigned): KmmResult<TokenStatus>? =
        issuerSigned.issuerAuth.payload?.status?.let {
            checkRevocationStatus(it)
        }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     */
    suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws): KmmResult<TokenStatus>? =
        vcJws.vc.credentialStatus?.let {
            checkRevocationStatus(it)
        }

    /**
     * Checks the revocation state of the passed Verifiable Credential.
     */
    suspend fun checkRevocationStatus(sdJwt: VerifiableCredentialSdJwt): KmmResult<TokenStatus>? =
        sdJwt.credentialStatus?.let {
            checkRevocationStatus(it)
        }

    /**
     * Checks the revocation state using the provided status mechanisms
     */
    private suspend fun checkRevocationStatus(status: Status): KmmResult<TokenStatus>? = try {
        val resolver = tokenStatusResolver ?: {
            TokenStatus.Valid
        }
        KmmResult.success(resolver.invoke(status))
    } catch (it: Throwable) {
        // A status mechanism is specified, but token status cannot be evaluated
        null
    }

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Presentation.
     *
     * @param challenge Nonce that the verifier has sent to the holder
     * @param clientId Identifier of the verifier (i.e. the audience of the presentation)
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyVpJws(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
        clientId: String,
    ): VerifyPresentationResult {
        Napier.d("Verifying VP $input with $challenge and $clientId")
        if (!verifyJwsObject(input)) {
            Napier.w("VP: Signature invalid")
            throw IllegalArgumentException("signature")
        }
        val parsedVp = parser.parseVpJws(input.payload, challenge, clientId)
        if (parsedVp !is Parser.ParseVpResult.Success) {
            Napier.d("VP: Could not parse content")
            throw (parsedVp as? Parser.ParseVpResult.ValidationError)?.cause
                ?: IllegalArgumentException("vp.content")
        }
        val parsedVcList = parsedVp.jws.vp.verifiableCredential
            .map { verifyVcJws(it, null) }
        val validVcList = parsedVcList
            .filterIsInstance<VerifyCredentialResult.SuccessJwt>()
            .map { it.jws }
        val revokedVcList = parsedVcList
            .filterIsInstance<VerifyCredentialResult.Revoked>()
            .map { it.jws }
        val invalidVcList = parsedVcList
            .filterIsInstance<VerifyCredentialResult.InvalidStructure>()
            .map { it.input }
        val vp = VerifiablePresentationParsed(
            id = parsedVp.jws.vp.id,
            type = parsedVp.jws.vp.type,
            verifiableCredentials = validVcList,
            revokedVerifiableCredentials = revokedVcList,
            invalidVerifiableCredentials = invalidVcList,
        )
        Napier.d("VP: Valid")
        return VerifyPresentationResult.Success(vp)
    }

    /**
     * Validates the content of a SD-JWT presentation, expected to contain a [VerifiableCredentialSdJwt],
     * as well as some disclosures and a key binding JWT at the end.
     *
     * @param challenge Expected challenge in the [KeyBindingJws] inside the [input]
     * @param clientId Identifier of the verifier, to verify audience of key binding JWS
     */
    suspend fun verifyVpSdJwt(
        input: SdJwtSigned,
        challenge: String,
        clientId: String,
        transactionData: Pair<PresentationRequestParameters.Flow, List<TransactionDataBase64Url>>?,
    ): VerifyPresentationResult {
        Napier.d("verifyVpSdJwt: '$input', '$challenge', '$clientId', '$transactionData'")
        val sdJwtResult = verifySdJwt(input, null)
        if (sdJwtResult !is VerifyCredentialResult.SuccessSdJwt) {
            Napier.w("verifyVpSdJwt: Could not verify SD-JWT: $sdJwtResult")
            val error = (sdJwtResult as? VerifyCredentialResult.ValidationError)?.cause
                ?: Throwable("SD-JWT not verified")
            return ValidationError(error)
        }
        val keyBindingSigned = sdJwtResult.sdJwtSigned.keyBindingJws ?: run {
            Napier.w("verifyVpSdJwt: No key binding JWT")
            return ValidationError("No key binding JWT")
        }
        val vcSdJwt = sdJwtResult.verifiableCredentialSdJwt
        if (vcSdJwt.confirmationClaim != null) {
            if (!verifyJwsSignatureWithCnf(keyBindingSigned, vcSdJwt.confirmationClaim)) {
                Napier.w("verifyVpSdJwt: Key binding JWT not verified with keys from cnf")
                return ValidationError("Key binding JWT not verified (from cnf)")
            }
        } else {
            if (!verifyJwsObject(keyBindingSigned)) {
                Napier.w("verifyVpSdJwt: Key binding JWT not verified")
                return ValidationError("Key binding JWT not verified")
            }
        }
        val keyBinding = keyBindingSigned.payload

        if (keyBinding.challenge != challenge) {
            Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}, expected $clientId")
            return ValidationError("Challenge not correct: ${keyBinding.challenge}")
        }
        if (keyBinding.audience != clientId) {
            Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}, expected $clientId")
            return ValidationError("Audience not correct: ${keyBinding.audience}")
        }
        if (!keyBinding.sdHash.contentEquals(input.hashInput.encodeToByteArray().sha256())) {
            Napier.w("verifyVpSdJwt: Key Binding does not contain correct sd_hash")
            return ValidationError("Key Binding does not contain correct sd_hash")
        }
        if (verifyTransactionData) {
            transactionData?.let { (flow, data) ->
                if (flow == PresentationRequestParameters.Flow.OID4VP) {
                    //TODO support more hash algorithms
                    if (keyBinding.transactionDataHashesAlgorithm != "sha-256") {
                        Napier.w("verifyVpSdJwt: Key Binding uses unsupported hashing algorithm. Please use sha256")
                        return ValidationError("verifyVpSdJwt: Key Binding uses unsupported hashing algorithm. Please use sha256")
                    }
                    if (keyBinding.transactionDataHashes?.contentEquals(data.map { it.sha256() }) == false) {
                        Napier.w("verifyVpSdJwt: Key Binding does not contain correct transaction data hashes")
                        return ValidationError("Key Binding does not contain correct transaction data hashes")
                    }
                } else if (keyBinding.transactionData?.contentEqualsIfArray(data) == false) {
                    Napier.w("verifyVpSdJwt: Key Binding does not contain correct transaction data hashes")
                    return ValidationError("Key Binding does not contain correct transaction data")
                }
            }
        }


        Napier.d("verifyVpSdJwt: Valid")
        return VerifyPresentationResult.SuccessSdJwt(
            sdJwtSigned = sdJwtResult.sdJwtSigned,
            verifiableCredentialSdJwt = vcSdJwt,
            reconstructedJsonObject = sdJwtResult.reconstructedJsonObject,
            disclosures = sdJwtResult.disclosures.values,
            isRevoked = sdJwtResult.isRevoked,
        )
    }

    /**
     * Validates an ISO device response, equivalent of a Verifiable Presentation
     */
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDeviceResponse(
        deviceResponse: DeviceResponse,
        verifyDocumentCallback: (MobileSecurityObject, Document) -> Boolean,
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
        verifyDocumentCallback: (MobileSecurityObject, Document) -> Boolean,
    ): IsoDocumentParsed {
        if (doc.errors != null) {
            Napier.w("Document has errors: ${doc.errors}")
            throw IllegalArgumentException("errors")
        }
        val issuerSigned = doc.issuerSigned
        val issuerAuth = issuerSigned.issuerAuth

        val certificateChain = issuerAuth.unprotectedHeader?.certificateChain?.firstOrNull() ?: run {
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
            isRevoked = checkRevocationStatus(issuerSigned)?.let {
                it.getOrThrow() == TokenStatus.Invalid
            },
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
        val verifierHash =
            vckCborSerializer.encodeToByteArray(ByteArraySerializer(), serialized).wrapInCborTag(24).sha256()
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
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult {
        Napier.d("Verifying VC-JWS $input")
        val jws = JwsSigned.deserialize<VerifiableCredentialJws>(
            VerifiableCredentialJws.serializer(),
            input,
            vckJsonSerializer
        ).getOrElse {
            Napier.w("VC: Could not parse JWS", it)
            return VerifyCredentialResult.InvalidStructure(input)
        }
        if (!verifyJwsObject(jws)) {
            Napier.w("VC: Signature invalid")
            return VerifyCredentialResult.InvalidStructure(input)
        }
        val vcJws = jws.payload
        publicKey?.let {
            if (!it.matchesIdentifier(vcJws.subject)) {
                Napier.d("VC: sub invalid")
                return VerifyCredentialResult.ValidationError("Sub invalid: ${vcJws.subject}")
            }
        }
        vcJws.vc.credentialStatus?.let {
            Napier.d("VC: status found")
            if (checkRevocationStatus(it)?.getOrNull() == TokenStatus.Invalid) {
                // TODO: how to handle case where resolving token status fails?
                Napier.d("VC: revoked")
                return VerifyCredentialResult.Revoked(input, vcJws)
            }
            Napier.d("VC: not revoked")
        }
        return when (val vcValid = parser.parseVcJws(input, vcJws)) {
            is Parser.ParseVcResult.InvalidStructure -> VerifyCredentialResult.InvalidStructure(input)
                .also { Napier.d("VC: Invalid structure from Parser") }

            is Parser.ParseVcResult.ValidationError -> VerifyCredentialResult.ValidationError(vcValid.cause)
                .also { Napier.d("VC: Validation error: $vcValid") }

            is Parser.ParseVcResult.Success -> VerifyCredentialResult.SuccessJwt(vcJws)
                .also { Napier.d("VC: Valid") }

            is Parser.ParseVcResult.SuccessSdJwt -> VerifyCredentialResult.SuccessJwt(vcJws)
                .also { Napier.d("VC: Valid") }

        }
    }

    /**
     * Validates the content of an [SdJwtSigned], expected to contain a [VerifiableCredentialSdJwt].
     *
     * @param publicKey Optionally the local key, to verify SD-JWT was bound to correct subject
     */
    suspend fun verifySdJwt(
        sdJwtSigned: SdJwtSigned,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $sdJwtSigned for $publicKey")
        if (!verifyJwsObject(sdJwtSigned.jws)) {
            Napier.w("verifySdJwt: Signature invalid")
            return VerifyCredentialResult.ValidationError("Signature not verified")
        }
        val sdJwt = sdJwtSigned.getPayloadAsVerifiableCredentialSdJwt().getOrElse { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
            return VerifyCredentialResult.ValidationError(ex)
        }
        // considering a failing attempt at retrieving the token status as "WE DO NOT KNOW"
        val isRevoked = checkRevocationStatus(sdJwt)?.let { result ->
            result.getOrNull()?.let {
                it == TokenStatus.Invalid // TODO: is this the only status we consider "revoked"?
            }
                ?: false // TODO: how to handle the case where resolving token status fails? Currently considered "not revoked"
        } ?: false

        if (isRevoked) { // How to handle "WE DO NOT KNOW"?
            Napier.d("verifySdJwt: revoked")
        }
        sdJwtSigned.getPayloadAsJsonObject().getOrElse { ex ->
            Napier.w("verifySdJwt: Could not parse payload", ex)
            return VerifyCredentialResult.ValidationError(ex)
        }

        val sdJwtValidator = SdJwtValidator(sdJwtSigned)
        val reconstructedJsonObject = sdJwtValidator.reconstructedJsonObject ?: buildJsonObject { }

        /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
        val validDisclosures: Map<String, SelectiveDisclosureItem> = sdJwtValidator.validDisclosures
        return when (val valid = parser.verifySdJwtValidity(sdJwt)) {
            is Parser.ParseVcResult.SuccessSdJwt -> VerifyCredentialResult.SuccessSdJwt(
                sdJwtSigned = sdJwtSigned,
                verifiableCredentialSdJwt = sdJwt,
                reconstructedJsonObject = reconstructedJsonObject,
                disclosures = validDisclosures,
                isRevoked = isRevoked
            ).also { Napier.d("verifySdJwt: Valid") }

            is Parser.ParseVcResult.ValidationError -> VerifyCredentialResult.ValidationError(valid.cause)
            else -> VerifyCredentialResult.ValidationError("Invalid time validity")
        }
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        if (issuerKey == null) {
            Napier.w("ISO: No issuer key")
            return VerifyCredentialResult.InvalidStructure(it.serialize().encodeToString(Base16(strict = true)))
        }
        verifyCoseSignatureWithKey(it.issuerAuth, issuerKey, byteArrayOf(), null).onFailure { ex ->
            Napier.w("ISO: Could not verify credential", ex)
            return VerifyCredentialResult.InvalidStructure(it.serialize().encodeToString(Base16(strict = true)))
        }
        return VerifyCredentialResult.SuccessIso(it)
    }
}

@Deprecated("Will not be thrown")
class TokenStatusEvaluationException(
    val delegate: Throwable,
) : Exception(delegate)