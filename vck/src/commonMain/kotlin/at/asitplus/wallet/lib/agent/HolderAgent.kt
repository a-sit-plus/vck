package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceRequest
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure
import at.asitplus.wallet.lib.validation.CheckOutcome
import at.asitplus.wallet.lib.validation.CredentialChecks
import at.asitplus.wallet.lib.validation.CredentialStorageResult
import at.asitplus.wallet.lib.validation.CredentialTrustAnchors
import at.asitplus.wallet.lib.validation.CredentialValidationContext
import at.asitplus.wallet.lib.validation.CredentialValidationInput
import at.asitplus.wallet.lib.validation.CredentialValidator
import at.asitplus.wallet.lib.validation.HolderBindingPolicy
import at.asitplus.wallet.lib.validation.StatusPolicy
import at.asitplus.wallet.lib.validation.TrustPolicy
import at.asitplus.wallet.lib.validation.ValidatedCredential
import at.asitplus.wallet.lib.validation.ValidationPolicy
import at.asitplus.wallet.lib.validation.firstRejection
import at.asitplus.wallet.lib.validation.sameForAllTypes
import at.asitplus.wallet.lib.zk.iso.IsoMdocZkEngine
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.encodeToByteArray
import kotlin.jvm.JvmOverloads
import kotlin.time.Duration.Companion.seconds

/**
 * An agent that only implements [Holder], i.e. it can receive credentials from other agents
 * and present credentials to other agents.
 */
class HolderAgent @JvmOverloads constructor(
    override val keyMaterial: KeyMaterial,
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val verifiablePresentationFactory: VerifiablePresentationFactory =
        VerifiablePresentationFactory(keyMaterial = keyMaterial),
    /**
     * Validates credentials before they are stored, see [storeCredentialWithReport], and orders stored credentials by
     * their time and status, see [getValidCredentialsByPriority]. Configure it with the trust anchors per credential
     * type and the status list token resolver; without trust anchors, [storeCredential] checks integrity only.
     */
    private val credentialValidator: CredentialValidator = CredentialValidator(),
) : Holder {

    @Deprecated(
        "The validator parameters no longer take effect, and trustedIssuers trusts every issuer for every credential" +
                " type: pass a credentialValidator with trust anchors per credential type instead"
    )
    @Suppress("DEPRECATION")
    constructor(
        keyMaterial: KeyMaterial,
        subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
        @Suppress("UNUSED_PARAMETER") validator: Validator? = null,
        trustedIssuers: TrustedCertificates? = null,
        @Suppress("UNUSED_PARAMETER") validatorVcJws: ValidatorVcJws? = null,
        @Suppress("UNUSED_PARAMETER") validatorSdJwt: ValidatorSdJwt? = null,
        @Suppress("UNUSED_PARAMETER") validatorMdoc: ValidatorMdoc? = null,
        signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> = SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
        signKeyBinding: SignJwtFun<KeyBindingJws> = SignJwt(keyMaterial, JwsHeaderNone()),
        signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> = SignCoseDetached(
            keyMaterial = keyMaterial,
            protectedHeaderModifier = CoseHeaderNone(),
            unprotectedHeaderModifier = CoseHeaderNone()
        ),
        mdocZkEngine: IsoMdocZkEngine = IsoMdocZkEngine(),
        verifiablePresentationFactory: VerifiablePresentationFactory = VerifiablePresentationFactory(
            keyMaterial = keyMaterial,
            signVerifiablePresentation = signVerifiablePresentation,
            signKeyBinding = signKeyBinding,
            mdocZkEngine = mdocZkEngine,
            signDeviceAuthDetached = signDeviceAuthDetached
        ),
        credentialValidator: CredentialValidator? = null,
    ) : this(
        keyMaterial = keyMaterial,
        subjectCredentialStore = subjectCredentialStore,
        verifiablePresentationFactory = verifiablePresentationFactory,
        credentialValidator = credentialValidator(trustedIssuers, credentialValidator),
    )

    private val presentationResponseCreator = PresentationResponseCreator(verifiablePresentationFactory)

    /**
     * The checks [storeCredential] has always made: issuer trust only if trust anchors are configured, and neither
     * time nor status, which are checked when credentials are used.
     */
    private val compatibilityPolicy = ValidationPolicy(
        trust = if (credentialValidator.hasTrustAnchors) TrustPolicy.RequireAuthorizedSigner
        else TrustPolicy.IntegrityOnly,
        status = StatusPolicy.Skip,
        timeLeeway = 300.seconds,
        requireTimeliness = false,
    )

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     *
     * Validates with [storeCredentialWithReport] under the checks this has always made, see [compatibilityPolicy], and
     * fails with the cause of the first check that rejects the credential.
     */
    override suspend fun storeCredential(
        credential: Holder.StoreCredentialInput,
        renewalInfo: CredentialRenewalInfo?
    ) = catching {
        val result = storeCredentialWithReport(credential, compatibilityPolicy, renewalInfo).getOrThrow()
        result.storedEntry ?: throw result.validation.report.firstRejection()
            ?: IllegalStateException("The credential has not been stored")
    }

    /**
     * Validates [credential] under [policy], bound to the key of this holder whatever [ValidationPolicy.holderBinding]
     * says, and of the type of its scheme, and stores it only if it is accepted, see [CredentialStorageResult].
     * A rejected credential is a successful result with its report; only persisting fails.
     */
    @JvmOverloads
    suspend fun storeCredentialWithReport(
        credential: Holder.StoreCredentialInput,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): KmmResult<CredentialStorageResult> = catching {
        val bound = policy.copy(holderBinding = HolderBindingPolicy.RequireExpectedKey)
        val validation = when (credential) {
            is Holder.StoreCredentialInput.Vc -> credentialValidator.validate(
                input = CredentialValidationInput.VcJwt(credential.vcJws),
                policy = bound,
                context = context(credential.scheme.vcType)
            )

            is Holder.StoreCredentialInput.SdJwt -> credentialValidator.validate(
                input = CredentialValidationInput.SdJwtVc(credential.vcSdJwt),
                policy = bound,
                context = context(credential.scheme.sdJwtType),
            )

            // Validates the encoding, which is what presentations of the credential carry
            is Holder.StoreCredentialInput.Iso -> credentialValidator.validate(
                input = CredentialValidationInput.IsoMdoc(coseCompliantSerializer.encodeToByteArray(credential.issuerSigned)),
                policy = bound,
                context = context(credential.scheme.isoDocType),
            )
        }
        CredentialStorageResult(validation, validation.credential?.let { store(credential, it, renewalInfo) })
    }

    private fun context(credentialIdentifier: String) = CredentialValidationContext(
        expectedHolderKey = keyMaterial.publicKey,
        expectedCredentialIdentifier = credentialIdentifier,
    )

    private suspend fun store(
        credential: Holder.StoreCredentialInput,
        accepted: ValidatedCredential,
        renewalInfo: CredentialRenewalInfo?,
    ): StoreEntry = when (credential) {
        is Holder.StoreCredentialInput.Vc -> subjectCredentialStore.storeCredential(
            vc = (accepted as ValidatedCredential.VcJwt).credential,
            vcSerialized = credential.vcJws,
            scheme = credential.scheme,
            renewalInfo = renewalInfo,
            issuer = credential.signedVcJws.jws.jwsHeader.certificateChain?.leaf
        )

        is Holder.StoreCredentialInput.SdJwt -> subjectCredentialStore.storeCredential(
            vc = (accepted as ValidatedCredential.SdJwtVc).credential,
            vcSerialized = credential.vcSdJwt,
            disclosures = accepted.disclosures,
            scheme = credential.scheme,
            renewalInfo = renewalInfo,
            issuer = credential.signedSdJwtVc.jws.jwsHeader.certificateChain?.leaf
        )

        is Holder.StoreCredentialInput.Iso -> subjectCredentialStore.storeCredential(
            issuerSigned = (accepted as ValidatedCredential.IsoMdoc).issuerSigned,
            scheme = credential.scheme,
            renewalInfo = renewalInfo,
            issuer = credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.getOrNull(0)
                ?.let { X509Certificate.decodeFromDer(it) }
        )
    }

    /**
     * Gets a list of all stored credentials, with a revocation status.
     */
    override suspend fun getCredentials(): Collection<StoreEntry>? =
        subjectCredentialStore.getCredentials().getOrNull()

    /**
     * Gets a list of all stored credentials sorted by preference, possibly filtered by [filterByIds]: credentials that
     * are verifiably expired, not yet valid, or of a status that is not accepted come last, see [hasVerifiedProblem].
     */
    private suspend fun getValidCredentialsByPriority(filterByIds: Collection<String>? = null): List<StoreEntry>? {
        val availableCredentials = getCredentials() ?: return null
        val presortedCredentials = availableCredentials
            .filter { filterByIds == null || filterByIds.contains(it.getDcApiId()) }
            .sortedBy { it.sortKey() }
        val demoted = coroutineScope {
            presortedCredentials.map { async { it.hasVerifiedProblem() } }.awaitAll()
        }
        return presortedCredentials.indices
            .sortedBy { if (demoted[it]) 1 else 0 }
            .map { presortedCredentials[it] }
    }

    /**
     * The checks for ordering stored credentials, see [hasVerifiedProblem]: they have been validated when stored, so
     * this checks time and status only, with status list signers trusted as when storing, see [compatibilityPolicy].
     */
    private val orderingPolicy = ValidationPolicy(
        trust = TrustPolicy.IntegrityOnly,
        status = StatusPolicy.ValidateIfPresent(signerTrust = compatibilityPolicy.trust),
        timeLeeway = compatibilityPolicy.timeLeeway,
        requireTimeliness = true,
    )

    /**
     * Whether this credential is verifiably expired or not yet valid, or has a verified status that is not accepted,
     * or conflicting statuses. A status that could not be verified, e.g. because the status list token is not
     * available, does not count, as it would demote every credential while offline.
     */
    private suspend fun StoreEntry.hasVerifiedProblem(): Boolean {
        val input = when (this) {
            is StoreEntry.Vc -> CredentialValidationInput.VcJwt(vcSerialized)
            is StoreEntry.SdJwt -> CredentialValidationInput.SdJwtVc(vcSerialized)
            is StoreEntry.Iso ->
                CredentialValidationInput.IsoMdoc(coseCompliantSerializer.encodeToByteArray(issuerSigned))
        }
        val checks = catchingUnwrapped {
            credentialValidator.validate(input, orderingPolicy).report.checks
        }.getOrNull() as? CredentialChecks ?: return false
        return checks.timeliness.outcome is CheckOutcome.Failed ||
                checks.status.mechanisms.any { it.outcome is CheckOutcome.Failed } ||
                checks.status.agreement is CheckOutcome.Failed
    }

    /** Prefer credentials with support for selective disclosure. */
    private fun StoreEntry.sortKey(): Int = when (this) {
        is StoreEntry.Vc -> 2
        is StoreEntry.SdJwt -> 1
        is StoreEntry.Iso -> 1
    }

    override suspend fun createDefaultPresentation(
        request: PresentationRequestParameters,
        credentialPresentationRequest: CredentialPresentationRequest,
    ): KmmResult<PresentationResponseParameters> =
        createPresentation(request, credentialPresentationRequest.toCredentialPresentation())

    /** Matches any supported presentation request while preserving its request-specific result type. */
    override suspend fun matchPresentationRequestAgainstCredentialStore(
        presentationRequest: CredentialPresentationRequest,
        filterByIds: Collection<String>?,
    ): KmmResult<CredentialMatchingResult<StoreEntry>> = catching {
        when (presentationRequest) {
            is CredentialPresentationRequest.DCQLRequest -> DCQLMatchingResult(
                presentationRequest = presentationRequest,
                matchingResult = matchDCQLQueryAgainstCredentialStoreV2(
                    dcqlQuery = presentationRequest.dcqlQuery,
                    filterByIds = filterByIds,
                ).getOrThrow(),
            )

            is CredentialPresentationRequest.IsoDeviceRetrieval -> IsoDeviceRetrievalMatchingResult(
                presentationRequest = presentationRequest,
                matchingResult = matchDeviceRetrievalAgainstCredentialStore(
                    deviceRequest = presentationRequest.deviceRequest,
                    filterByIds = filterByIds,
                ).getOrThrow(),
            )
        }
    }

    override suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters> = presentationResponseCreator.create(
        request = request,
        credentialPresentation = credentialPresentation,
        matchDCQLQuery = { matchDCQLQueryAgainstCredentialStoreV2(it) },
        matchDeviceRequest = { matchDeviceRetrievalAgainstCredentialStore(it) },
    )

    suspend fun matchDeviceRetrievalAgainstCredentialStore(
        deviceRequest: DeviceRequest,
        filterByIds: Collection<String>? = null,
    ): KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>> = catching {
        val credentials = getValidCredentialsByPriority(filterByIds)
            ?: throw PresentationException("Credentials could not be retrieved from the store")
        HolderIsoDeviceRetrievalQueryMatchingResult(
            credentials = credentials,
            queryMatchingResult = DeviceRetrievalProcedure.match(deviceRequest, credentials),
        )
    }

    private suspend fun matchDCQLQueryAgainstCredentialStoreV2(
        dcqlQuery: DCQLQuery,
        filterByIds: Collection<String>? = null,
    ): KmmResult<HolderDCQLQueryMatchingResult<StoreEntry>> = catching {
        val credentials = getValidCredentialsByPriority(filterByIds)
            ?: throw PresentationException("Credentials could not be retrieved from the store")
        HolderDCQLQueryMatchingResult(
            dcqlQueryMatchingResult = DCQLQueryAdapter(dcqlQuery).select(
                credentials = credentials
            ),
            credentials = credentials,
        )
    }

}

/** The validator the deprecated [HolderAgent] constructor uses: [trustedIssuers] for every credential type. */
private fun credentialValidator(
    trustedIssuers: TrustedCertificates?,
    credentialValidator: CredentialValidator?,
): CredentialValidator {
    require(trustedIssuers == null || credentialValidator == null) {
        "Set either trustedIssuers or credentialValidator, not both"
    }
    return credentialValidator ?: CredentialValidator(
        trustAnchors = trustedIssuers?.let {
            CredentialTrustAnchors.sameForAllTypes(issuance = it, status = null, source = "trustedIssuers")
        }
    )
}
