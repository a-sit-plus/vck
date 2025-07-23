package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsSigned
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
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.jws.*
import io.github.aakira.napier.Napier
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.datetime.Clock
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
    @Deprecated("Use parameter in `CredentialTimelinessValidator` instead")
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

    private val validatorVcJws = ValidatorVcJws(
        verifySignature = verifySignature,
        verifyJwsSignature = verifyJwsSignature,
        verifyJwsObject = verifyJwsObject,
        vcJwsInputValidator = vcJwsInputValidator,
        validator = this
    )

    @Throws(IllegalArgumentException::class, CancellationException::class)
    @Deprecated("Use method from ValidatorVcJws instead")
    suspend fun verifyVpJws(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
        clientId: String,
    ): VerifyPresentationResult = validatorVcJws.verifyVpJws(input, challenge, clientId)

    @Deprecated("Use method from ValidatorVcJws instead")
    suspend fun verifyVcJws(
        input: JwsSigned<VerifiableCredentialJws>,
        publicKey: CryptoPublicKey?,
    ) = validatorVcJws.verifyVcJws(input, publicKey)

    @Deprecated("Use method from ValidatorVcJws instead")
    suspend fun verifyVcJws(
        input: String,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult = validatorVcJws.verifyVcJws(input, publicKey)

    private val validatorSdJwt = ValidatorSdJwt(
        verifySignature = verifySignature,
        verifyJwsSignature = verifyJwsSignature,
        verifyJwsObject = verifyJwsObject,
        verifyTransactionData = verifyTransactionData,
        sdJwtInputValidator = sdJwtInputValidator,
        validator = this
    )

    @Deprecated("Use method from ValidatorSdJwt instead")
    suspend fun verifyVpSdJwt(
        input: SdJwtSigned,
        challenge: String,
        clientId: String,
        transactionData: Pair<PresentationRequestParameters.Flow, List<TransactionDataBase64Url>>?,
    ): VerifyPresentationResult = validatorSdJwt.verifyVpSdJwt(input, challenge, clientId, transactionData)

    @Deprecated("Use method from ValidatorSdJwt instead")
    suspend fun verifySdJwt(
        sdJwtSigned: SdJwtSigned,
        publicKey: CryptoPublicKey?,
    ): VerifyCredentialResult = validatorSdJwt.verifySdJwt(sdJwtSigned, publicKey)

    private val validatorMdoc = ValidatorMdoc(
        verifySignature = verifySignature,
        verifyCoseSignatureWithKey = verifyCoseSignatureWithKey,
        mdocInputValidator = mdocInputValidator,
        validator = this
    )

    @Deprecated("Use method from ValidatorMdoc instead")
    @Throws(IllegalArgumentException::class, CancellationException::class)
    suspend fun verifyDeviceResponse(
        deviceResponse: DeviceResponse,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult = validatorMdoc.verifyDeviceResponse(deviceResponse, verifyDocumentCallback)

    @Throws(IllegalArgumentException::class, CancellationException::class)
    @Deprecated("Use method from ValidatorMdoc instead")
    suspend fun verifyDocument(
        doc: Document,
        verifyDocumentCallback: suspend (MobileSecurityObject, Document) -> Boolean,
    ): IsoDocumentParsed = validatorMdoc.verifyDocument(doc, verifyDocumentCallback)

    @Deprecated("Use method from ValidatorMdoc instead")
    suspend fun verifyIsoCred(it: IssuerSigned, issuerKey: CoseKey?): VerifyCredentialResult =
        validatorMdoc.verifyIsoCred(it, issuerKey)
}
