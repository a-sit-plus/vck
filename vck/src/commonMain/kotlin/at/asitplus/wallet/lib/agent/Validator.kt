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
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult.*
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.*
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidator
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsTimelinessValidator
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.iso.*
import at.asitplus.wallet.lib.jws.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class Validator(
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(verifyJwsSignature),
    private val verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> =
        VerifyCoseSignatureWithKey(verifySignature),
    private val parser: Parser = Parser(),
    /**
     * Toggles whether transaction data should be verified if present
     */
    private val verifyTransactionData: Boolean = true,
    /**
     * Structure / Integrity / Semantics validator for each credential
     */
    private val vcJwsInputValidator: VcJwsInputValidator = VcJwsInputValidator(
        verifyJwsObject = verifyJwsObject,
    ),
    private val sdJwtInputValidator: SdJwtInputValidator = SdJwtInputValidator(
        verifyJwsObject = verifyJwsObject,
    ),
    private val mdocInputValidator: MdocInputValidator = MdocInputValidator(
        verifyCoseSignatureWithKey = verifyCoseSignatureWithKey,
    ),
    /**
     * @param timeLeeway specifies tolerance for expiration and start of validity of credentials.
     * A credential that expired at most `timeLeeway` ago is not yet considered expired.
     * A credential that is valid in at most `timeLeeway` is already considered valid.
     */
    private val timeLeeway: Duration = 300.seconds,
    private val clock: Clock = Clock.System,
    private val zlibService: ZlibService = DefaultZlibService(),
    private val resolveStatusListToken: StatusListTokenResolver? = null,
    /**
     * The function [tokenStatusResolver] should check the status mechanisms in a given status claim in order to
     * evaluate the token status.
     */
    private val tokenStatusResolver: TokenStatusResolver = resolveStatusListToken?.toTokenStatusResolver(
        verifyJwsObjectIntegrity = verifyJwsObject,
        zlibService = zlibService,
        verifyCoseSignature = verifyCoseSignature,
        clock = clock,
    ) ?: TokenStatusResolver {
        KmmResult.success(TokenStatus.Valid)
    },
    private val vcJwsTimelinessValidator: VcJwsTimelinessValidator = VcJwsTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock,
    ),
    private val sdJwtTimelinessValidator: SdJwtTimelinessValidator = SdJwtTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock,
    ),
    private val mdocTimelinessValidator: MdocTimelinessValidator = MdocTimelinessValidator(
        timeLeeway = timeLeeway,
        clock = clock,
    ),
    private val credentialTimelinessValidator: CredentialTimelinessValidator = CredentialTimelinessValidator(
        clock = clock,
        timeLeeway = timeLeeway,
        vcJwsTimelinessValidator = vcJwsTimelinessValidator,
        sdJwtTimelinessValidator = sdJwtTimelinessValidator,
        mdocTimelinessValidator = mdocTimelinessValidator,
    ),
) {
    /**
     * Checks the timeliness of the passed credential.
     */
    fun checkTimeliness(storeEntry: SubjectCredentialStore.StoreEntry) = credentialTimelinessValidator(storeEntry)
    fun checkTimeliness(issuerSigned: IssuerSigned) = credentialTimelinessValidator(issuerSigned)
    fun checkTimeliness(vcJws: VerifiableCredentialJws) = credentialTimelinessValidator(vcJws)
    fun checkTimeliness(sdJwt: VerifiableCredentialSdJwt) = credentialTimelinessValidator(sdJwt)

    /**
     * Checks the revocation state of the passed credential.
     */
    suspend fun checkRevocationStatus(storeEntry: SubjectCredentialStore.StoreEntry) = tokenStatusResolver(storeEntry)
    suspend fun checkRevocationStatus(issuerSigned: IssuerSigned): KmmResult<TokenStatus>? = tokenStatusResolver(issuerSigned)
    suspend fun checkRevocationStatus(sdJwt: VerifiableCredentialSdJwt): KmmResult<TokenStatus>? = tokenStatusResolver(sdJwt)
    suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws): KmmResult<TokenStatus>?  = tokenStatusResolver(vcJws)

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
            throw IllegalArgumentException("vp.content")
        }
        val vcValidationResults = parsedVp.jws.vp.verifiableCredential
            .map { it to verifyVcJws(it, null) }

        val invalidVcList = vcValidationResults.filter {
            it.second !is SuccessJwt
        }.map {
            it.first
        }

        val isTimelyGrouping = vcValidationResults.map {
            it.second
        }.filterIsInstance<SuccessJwt>().map {
            it.jws
        }.map {
            VcJwsVerificationResultWrapper(
                vcJws = it,
                tokenStatus = tokenStatusResolver(
                    CredentialWrapper.VcJws(it)
                ),
                timelinessValidationSummary = credentialTimelinessValidator(it),
            )
        }.groupBy {
            it.timelinessValidationSummary.isSuccess && it.tokenStatus?.let {
                // The library should probably not implicitly consider credentials valid if it isn't clear.
                // Valid credentials should probably require no further considerations.
                // Only consider TokenStatus.Valid is therefore implicitly considered valid.
                //  - If other credentials shall be accepted, those can be selected from `untimelyVerifiableCredentials`
                //      - selection should consider their token and expiration time status.
                it.getOrNull() == TokenStatus.Valid
            } ?: true
        }

        val vp = VerifiablePresentationParsed(
            id = parsedVp.jws.vp.id,
            type = parsedVp.jws.vp.type,
            timelyVerifiableCredentials = isTimelyGrouping[true] ?: listOf(),
            untimelyVerifiableCredentials = isTimelyGrouping[false] ?: listOf(),
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
        if (sdJwtResult !is SuccessSdJwt) {
            Napier.w("verifyVpSdJwt: Could not verify SD-JWT: $sdJwtResult")
            return VerifyPresentationResult.ValidationError("SD-JWT not verified")
        }
        val keyBindingSigned = sdJwtResult.sdJwtSigned.keyBindingJws ?: run {
            Napier.w("verifyVpSdJwt: No key binding JWT")
            return VerifyPresentationResult.ValidationError("No key binding JWT")
        }
        val vcSdJwt = sdJwtResult.verifiableCredentialSdJwt
        if (vcSdJwt.confirmationClaim != null) {
            if (!verifyJwsSignatureWithCnf(keyBindingSigned, vcSdJwt.confirmationClaim)) {
                Napier.w("verifyVpSdJwt: Key binding JWT not verified with keys from cnf")
                return VerifyPresentationResult.ValidationError("Key binding JWT not verified (from cnf)")
            }
        } else {
            if (!verifyJwsObject(keyBindingSigned)) {
                Napier.w("verifyVpSdJwt: Key binding JWT not verified")
                return VerifyPresentationResult.ValidationError("Key binding JWT not verified")
            }
        }
        val keyBinding = keyBindingSigned.payload

        if (keyBinding.challenge != challenge) {
            Napier.w("verifyVpSdJwt: Challenge not correct: ${keyBinding.challenge}, expected $clientId")
            return VerifyPresentationResult.ValidationError("Challenge not correct: ${keyBinding.challenge}")
        }
        if (keyBinding.audience != clientId) {
            Napier.w("verifyVpSdJwt: Audience not correct: ${keyBinding.audience}, expected $clientId")
            return VerifyPresentationResult.ValidationError("Audience not correct: ${keyBinding.audience}")
        }
        if (!keyBinding.sdHash.contentEquals(input.hashInput.encodeToByteArray().sha256())) {
            Napier.w("verifyVpSdJwt: Key Binding does not contain correct sd_hash")
            return VerifyPresentationResult.ValidationError("Key Binding does not contain correct sd_hash")
        }
        if (verifyTransactionData) {
            transactionData?.let { (flow, data) ->
                if (flow == PresentationRequestParameters.Flow.OID4VP) {
                    //TODO support more hash algorithms
                    if (keyBinding.transactionDataHashesAlgorithm != "sha-256") {
                        Napier.w("verifyVpSdJwt: Key Binding uses unsupported hashing algorithm. Please use sha256")
                        return VerifyPresentationResult.ValidationError("verifyVpSdJwt: Key Binding uses unsupported hashing algorithm. Please use sha256")
                    }
                    if (keyBinding.transactionDataHashes?.contentEquals(data.map { it.sha256() }) == false) {
                        Napier.w("verifyVpSdJwt: Key Binding does not contain correct transaction data hashes")
                        return VerifyPresentationResult.ValidationError("Key Binding does not contain correct transaction data hashes")
                    }
                } else if (keyBinding.transactionData?.contentEqualsIfArray(data) == false) {
                    Napier.w("verifyVpSdJwt: Key Binding does not contain correct transaction data hashes")
                    return VerifyPresentationResult.ValidationError("Key Binding does not contain correct transaction data")
                }
            }
        }


        Napier.d("verifyVpSdJwt: Valid")
        return VerifyPresentationResult.SuccessSdJwt(
            sdJwtSigned = sdJwtResult.sdJwtSigned,
            verifiableCredentialSdJwt = vcSdJwt,
            reconstructedJsonObject = sdJwtResult.reconstructedJsonObject,
            disclosures = sdJwtResult.disclosures.values,
            timelinessValidationSummary = checkTimeliness(sdJwtResult.verifiableCredentialSdJwt),
            tokenStatus = checkRevocationStatus(sdJwtResult.verifiableCredentialSdJwt)
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

        val certificateChain = issuerAuth.unprotectedHeader?.certificateChain?: run {
            Napier.w("Got no issuer certificate in $issuerAuth")
            throw IllegalArgumentException("issuerKey")
        }
        val x509Certificate = X509Certificate.decodeFromDerSafe(certificateChain.first()).getOrElse {
            Napier.w(
                "Could not parse issuer certificate in ${certificateChain.joinToString{it.encodeToString(Base64())}}",
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
            tokenStatus = checkRevocationStatus(issuerSigned),
            timelinessValidationSummary = checkTimeliness(issuerSigned)
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
        Napier.d("Validating VC-JWS $input")
        val validationSummary = vcJwsInputValidator(input, publicKey)
        return when {
            validationSummary !is VcJwsInputValidationResult.ContentValidationSummary -> InvalidStructure(input)
            !validationSummary.isIntegrityGood -> InvalidStructure(input)
            !validationSummary.contentSemanticsValidationSummary.isSuccess -> InvalidStructure(input)
            validationSummary.subjectMatchingResult?.isSuccess == false -> ValidationError(input)
            validationSummary.isSuccess -> SuccessJwt(validationSummary.payload)
            else -> ValidationError(input) // this branch shouldn't be executed happen anyway
        }
    }

    /**
     * Validates the content of an [SdJwtSigned], expected to contain a [VerifiableCredentialSdJwt].
     *
     * @param publicKey Optionally the local key, to verify SD-JWT was issued to correct subject
     */
    suspend fun verifySdJwt(
        sdJwtSigned: SdJwtSigned,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $sdJwtSigned for $publicKey")
        val validationResult = sdJwtInputValidator.invoke(sdJwtSigned, publicKey)
        return when {
            !validationResult.isIntegrityGood -> ValidationError("Signature not verified")
            validationResult.payloadCredentialValidationSummary.getOrNull()?.isSuccess == false -> ValidationError("subject invalid")

            else -> validationResult.payload.getOrElse {
                return ValidationError(it)
            }
        }
    }

    /**
     * Validates the content of a [IssuerSigned] object.
     *
     * @param it The [IssuerSigned] structure from ISO 18013-5
     */
    fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): VerifyCredentialResult {
        Napier.d("Verifying ISO Cred $it")
        if (!mdocInputValidator(it, issuerKey).isSuccess) {
            return InvalidStructure(it.serialize().encodeToString(Base16(strict = true)))
        }
        return SuccessIso(it)
    }
}