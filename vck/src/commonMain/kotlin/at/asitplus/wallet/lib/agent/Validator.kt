package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.iso.ValueDigestList
import at.asitplus.iso.sha256
import at.asitplus.iso.wrapInCborTag
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.openid.contentEquals
import at.asitplus.openid.sha256
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
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
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidationResult
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.data.VcDataModelConstants.VERIFIABLE_PRESENTATION
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.jws.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.encodeToByteArray
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
    /** Toggles whether transaction data should be verified if present. */
    private val verifyTransactionData: Boolean = true,
    /** Structure / Integrity / Semantics validator. */
    private val vcJwsInputValidator: VcJwsInputValidator =
        VcJwsInputValidator(verifyJwsObject = verifyJwsObject),
    /** Structure / Integrity / Semantics validator. */
    private val sdJwtInputValidator: SdJwtInputValidator =
        SdJwtInputValidator(verifyJwsObject = verifyJwsObject),
    /** Structure / Integrity / Semantics validator. */
    private val mdocInputValidator: MdocInputValidator =
        MdocInputValidator(verifyCoseSignatureWithKey = verifyCoseSignatureWithKey),
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
     * extract the token status.
     */
    private val tokenStatusResolver: TokenStatusResolver = resolveStatusListToken?.toTokenStatusResolver(
        verifyJwsObjectIntegrity = verifyJwsObject,
        zlibService = zlibService,
        verifyCoseSignature = verifyCoseSignature,
        clock = clock,
    ) ?: TokenStatusResolver {
        KmmResult.success(TokenStatus.Valid)
    },
    private val acceptedTokenStatuses: Set<TokenStatus> = setOf(TokenStatus.Valid),
    private val tokenStatusValidator: TokenStatusValidator =
        tokenStatusResolver.toTokenStatusValidator(acceptedTokenStatuses),
    private val credentialTimelinessValidator: CredentialTimelinessValidator =
        CredentialTimelinessValidator(clock = clock, timeLeeway = timeLeeway),
) {
    /**
     * Checks both the timeliness and the token status of the passed credentials
     */
    suspend fun checkCredentialFreshness(storeEntry: SubjectCredentialStore.StoreEntry) = when (storeEntry) {
        is SubjectCredentialStore.StoreEntry.Iso -> checkCredentialFreshness(storeEntry.issuerSigned)
        is SubjectCredentialStore.StoreEntry.SdJwt -> checkCredentialFreshness(storeEntry.sdJwt)
        is SubjectCredentialStore.StoreEntry.Vc -> checkCredentialFreshness(storeEntry.vc)
    }

    suspend fun checkCredentialFreshness(issuerSigned: IssuerSigned) = CredentialFreshnessSummary.Mdoc(
        tokenStatusValidationResult = checkRevocationStatus(issuerSigned),
        timelinessValidationSummary = credentialTimelinessValidator(issuerSigned)
    )

    suspend fun checkCredentialFreshness(sdJwt: VerifiableCredentialSdJwt) = CredentialFreshnessSummary.SdJwt(
        tokenStatusValidationResult = checkRevocationStatus(sdJwt),
        timelinessValidationSummary = credentialTimelinessValidator(sdJwt)
    )

    suspend fun checkCredentialFreshness(vcJws: VerifiableCredentialJws) = CredentialFreshnessSummary.VcJws(
        tokenStatusValidationResult = checkRevocationStatus(vcJws),
        timelinessValidationSummary = credentialTimelinessValidator(vcJws)
    )

    internal fun checkCredentialTimeliness(vcJws: VerifiableCredentialJws) = credentialTimelinessValidator(vcJws)

    /**
     * Checks the revocation state of the passed credential.
     */
    internal suspend fun checkRevocationStatus(storeEntry: SubjectCredentialStore.StoreEntry) =
        tokenStatusValidator(storeEntry)

    internal suspend fun checkRevocationStatus(issuerSigned: IssuerSigned) = tokenStatusValidator(issuerSigned)
    internal suspend fun checkRevocationStatus(sdJwt: VerifiableCredentialSdJwt) = tokenStatusValidator(sdJwt)
    internal suspend fun checkRevocationStatus(vcJws: VerifiableCredentialJws) = tokenStatusValidator(vcJws)

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
        val vpJws = input.payload.validate(challenge, clientId)
        val vcValidationResults = vpJws.vp.verifiableCredential
            .map { it to verifyVcJws(it, null) }

        val invalidVcList = vcValidationResults.filter {
            it.second !is SuccessJwt
        }.map {
            it.first
        }

        val verificationResultWithFreshnessSummary = vcValidationResults.map {
            it.second
        }.filterIsInstance<SuccessJwt>().map {
            it.jws
        }.map {
            VcJwsVerificationResultWrapper(
                vcJws = it,
                freshnessSummary = checkCredentialFreshness(it),
            )
        }

        val vp = VerifiablePresentationParsed(
            id = vpJws.vp.id,
            type = vpJws.vp.type,
            freshVerifiableCredentials = verificationResultWithFreshnessSummary.filter {
                it.freshnessSummary.isFresh
            },
            notVerifiablyFreshVerifiableCredentials = verificationResultWithFreshnessSummary.filter {
                !it.freshnessSummary.isFresh
            },
            invalidVerifiableCredentials = invalidVcList,
        )
        Napier.d("VP: Valid")

        return VerifyPresentationResult.Success(vp)
    }

    @Throws(IllegalArgumentException::class)
    fun VerifiablePresentationJws.validate(
        challenge: String,
        clientId: String,
    ): VerifiablePresentationJws {
        if (this.challenge != challenge) {
            Napier.w("nonce invalid")
            throw IllegalArgumentException("nonce invalid")
        }
        if (clientId != audience) {
            Napier.w("aud invalid: ${audience}, expected $clientId}")
            throw IllegalArgumentException("aud invalid: $audience")
        }
        if (jwtId != vp.id) {
            Napier.w("jti invalid: ${jwtId}, expected ${vp.id}")
            throw IllegalArgumentException("jti invalid: $jwtId")
        }
        if (vp.type != VERIFIABLE_PRESENTATION) {
            Napier.w("type invalid: ${vp.type}, expected $VERIFIABLE_PRESENTATION")
            throw IllegalArgumentException("type invalid: ${vp.type}")
        }
        Napier.d("VP is valid")
        return this
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
            val error = (sdJwtResult as? ValidationError)?.cause
                ?: Throwable("SD-JWT not verified")
            return VerifyPresentationResult.ValidationError(error)
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
                @Suppress("DEPRECATION")
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
            freshnessSummary = checkCredentialFreshness(sdJwtResult.verifiableCredentialSdJwt),
        )
    }

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
            freshnessSummary = checkCredentialFreshness(issuerSigned),
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
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally, the local key, to verify VC was issued to the correct subject
     */
    suspend fun verifyVcJws(
        input: JwsSigned<VerifiableCredentialJws>,
        publicKey: CryptoPublicKey?,
    ) = verifyVcJws(input.serialize(), publicKey)

    /**
     * Validates the content of a JWS, expected to contain a Verifiable Credential.
     *
     * @param input JWS in compact representation
     * @param publicKey Optionally, the local key, to verify VC was issued to the correct subject
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
            validationSummary.subjectMatchingResult?.isSuccess == false -> ValidationError("subject not matching key")
            validationSummary.isSuccess -> SuccessJwt(validationSummary.payload)
            else -> ValidationError(input) // this branch shouldn't be executed anyway
        }
    }

    /**
     * Validates the content of an [SdJwtSigned], expected to contain a [VerifiableCredentialSdJwt].
     *
     * @param publicKey Optionally, the local key, to verify SD-JWT was bound to it
     */
    suspend fun verifySdJwt(
        sdJwtSigned: SdJwtSigned,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult {
        Napier.d("Verifying SD-JWT $sdJwtSigned for $publicKey")
        val validationResult = sdJwtInputValidator.invoke(sdJwtSigned, publicKey)
        return when {
            !validationResult.isIntegrityGood -> ValidationError("Signature not verified")
            validationResult.payloadCredentialValidationSummary.getOrNull()?.isSuccess == false
                -> ValidationError("cnf claim invalid")

            else -> validationResult.payload.getOrElse { return ValidationError(it) }
        }
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
