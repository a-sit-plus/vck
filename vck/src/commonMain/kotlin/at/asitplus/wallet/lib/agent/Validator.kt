package at.asitplus.wallet.lib.agent

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.cosef.CoseKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.DefaultZlibService
import at.asitplus.wallet.lib.ZlibService
import at.asitplus.wallet.lib.agent.Verifier.VerifyCredentialResult
import at.asitplus.wallet.lib.agent.Verifier.VerifyPresentationResult
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidator
import at.asitplus.wallet.lib.agent.validation.StatusListTokenResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolver
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverImpl
import at.asitplus.wallet.lib.agent.validation.TokenStatusResolverNoop
import at.asitplus.wallet.lib.agent.validation.TokenStatusValidator
import at.asitplus.wallet.lib.agent.validation.invoke
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocInputValidator
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.agent.validation.toTokenStatusValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.cbor.VerifyCoseSignature
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureFun
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKey
import at.asitplus.wallet.lib.cbor.VerifyCoseSignatureWithKeyFun
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.StatusListTokenPayload
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.jws.SdJwtSigned
import at.asitplus.wallet.lib.jws.VerifyJwsObject
import at.asitplus.wallet.lib.jws.VerifyJwsObjectFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignature
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureFun
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnf
import at.asitplus.wallet.lib.jws.VerifyJwsSignatureWithCnfFun
import kotlinx.datetime.Clock
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Parses and validates Verifiable Credentials and Verifiable Presentations.
 * Does verify the cryptographic authenticity of the data.
 * Does verify the revocation status of the data (when a status information is encoded in the credential).
 */
class Validator(
    @Deprecated("Has been moved to [ValidatorSdJwt], [ValidatorVcJws], [ValidatorMdoc]")
    private val verifySignature: VerifySignatureFun = VerifySignature(),
    @Deprecated("Has been moved to [ValidatorSdJwt], [ValidatorVcJws]")
    private val verifyJwsSignature: VerifyJwsSignatureFun = VerifyJwsSignature(verifySignature),
    @Deprecated("Has been moved to [ValidatorSdJwt], [ValidatorVcJws]")
    private val verifyJwsObject: VerifyJwsObjectFun = VerifyJwsObject(verifyJwsSignature),
    @Deprecated("Has been moved to [ValidatorSdJwt]")
    private val verifyJwsSignatureWithCnf: VerifyJwsSignatureWithCnfFun = VerifyJwsSignatureWithCnf(verifyJwsSignature),
    @Deprecated("Has been moved to [ValidatorMdoc]")
    private val verifyCoseSignature: VerifyCoseSignatureFun<StatusListTokenPayload> = VerifyCoseSignature(),
    @Deprecated("Has been moved to [ValidatorMdoc]")
    private val verifyCoseSignatureWithKey: VerifyCoseSignatureWithKeyFun<MobileSecurityObject> =
        VerifyCoseSignatureWithKey(verifySignature),
    @Deprecated("Has been moved to [ValidatorSdJwt]")
    private val verifyTransactionData: Boolean = true,
    @Deprecated("Has been moved to [ValidatorVcJws]")
    private val vcJwsInputValidator: VcJwsInputValidator =
        VcJwsInputValidator(verifyJwsObject = verifyJwsObject),
    @Deprecated("Has been moved to [ValidatorSdJwt]")
    private val sdJwtInputValidator: SdJwtInputValidator =
        SdJwtInputValidator(verifyJwsObject = verifyJwsObject),
    @Deprecated("Has been moved to [ValidatorMdoc]")
    private val mdocInputValidator: MdocInputValidator =
        MdocInputValidator(verifyCoseSignatureWithKey = verifyCoseSignatureWithKey),
    @Deprecated("Use parameter in [CredentialTimelinessValidator] instead")
    private val timeLeeway: Duration = 300.seconds,
    @Deprecated("Use parameter in [tokenStatusResolver], [credentialTimelinessValidator] instead")
    private val clock: Clock = Clock.System,
    @Deprecated("Use parameter in [tokenStatusResolver] instead")
    private val zlibService: ZlibService = DefaultZlibService(),
    @Deprecated("Use [TokenStatusResolverImpl] for [tokenStatusResolver] instead")
    private val resolveStatusListToken: StatusListTokenResolver? = null,
    /** Clients may use [TokenStatusResolverImpl]. */
    private val tokenStatusResolver: TokenStatusResolver = TokenStatusResolverNoop,
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

    @Suppress("DEPRECATION")
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

    @Suppress("DEPRECATION")
    private val validatorSdJwt = ValidatorSdJwt(
        verifySignature = verifySignature,
        verifyJwsSignature = verifyJwsSignature,
        verifyJwsObject = verifyJwsObject,
        verifyJwsSignatureWithCnf = verifyJwsSignatureWithCnf,
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

    @Suppress("DEPRECATION")
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
