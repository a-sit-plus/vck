package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceRequest
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialScheme
import at.asitplus.wallet.lib.data.IsoMdocCredentialScheme
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.SdJwtCredentialScheme
import at.asitplus.wallet.lib.data.VcJwtCredentialScheme
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
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
import at.asitplus.wallet.lib.validation.CredentialValidationResult
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
     * their time and status, see [getValidCredentialsByPriority], unless [orderingValidator] is set. Configure it with
     * the trust anchors per credential type and the status list token resolver; without trust anchors,
     * [storeCredential] checks integrity only.
     */
    private val credentialValidator: CredentialValidator = CredentialValidator(),
    /**
     * Orders stored credentials by their time and status when matching them against a presentation request, see
     * [getValidCredentialsByPriority]: e.g. with a status list token resolver that returns cached tokens only, so
     * that matching, and creating a presentation, never waits for the network. A status that can not be resolved
     * does not demote a credential. By default [credentialValidator].
     */
    private val orderingValidator: CredentialValidator = credentialValidator,
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
     *
     * To let the user decide about a rejected credential, use [prepareCredentialStorage] instead.
     */
    @JvmOverloads
    suspend fun storeCredentialWithReport(
        credential: Holder.StoreCredentialInput,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): KmmResult<CredentialStorageResult> = catching {
        storeAccepted(prepareCredentialStorage(credential, policy, renewalInfo).getOrThrow()).getOrThrow()
    }

    /**
     * Validates [credential] like [storeCredentialWithReport], but stores nothing yet, e.g. as the last step of
     * issuance, so that the wallet can show the report to the user, e.g. an untrusted issuer or missing required
     * claims (see [ValidationPolicy.requiredClaims]). Then store it with [storeAccepted], or, if the user accepts a
     * rejected report, with [storeAfterUserConsent]. Fails only if the credential can not be validated at all.
     */
    @JvmOverloads
    suspend fun prepareCredentialStorage(
        credential: Holder.StoreCredentialInput,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): KmmResult<PreparedCredentialStorage> = catching {
        PreparedCredentialStorage(credential, validate(credential, policy), renewalInfo, keyMaterial.publicKey)
    }

    /**
     * Validates the encoded credential [input] of the type of [scheme], e.g. as received from a credential issuer, like
     * [prepareCredentialStorage], and decodes it only once: the credential to store is the one that has been
     * validated, e.g. an mdoc with exactly the bytes the issuer signed. Its [PreparedCredentialStorage.credential] is
     * `null` if it is not intact, as it can never be stored then.
     *
     * Fails if [scheme] does not support the representation of [input].
     */
    @JvmOverloads
    suspend fun prepareCredentialStorage(
        input: CredentialValidationInput,
        scheme: CredentialScheme,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): KmmResult<PreparedCredentialStorage> = catching {
        val validation = credentialValidator.validate(
            input = input,
            policy = policy.boundToHolder(),
            context = context(scheme.credentialIdentifier(input))
        )
        PreparedCredentialStorage(
            credential = validation.unacceptedCredential?.let { input.toStoreCredentialInput(it, scheme) },
            validation = validation,
            renewalInfo = renewalInfo,
            holderKey = keyMaterial.publicKey,
        )
    }

    /**
     * Prepares a credential that could not be decoded from its transfer encoding, e.g. the base64url encoding of an
     * mdoc in an OpenID4VCI credential response, so that it is reported like every other credential: rejected
     * under [policy], see [CredentialValidator.rejectUndecodable], and never stored.
     */
    @JvmOverloads
    fun rejectUndecodable(
        cause: Throwable,
        policy: ValidationPolicy,
        renewalInfo: CredentialRenewalInfo? = null,
    ): PreparedCredentialStorage = PreparedCredentialStorage(
        credential = null,
        validation = credentialValidator.rejectUndecodable(cause, policy.boundToHolder()),
        renewalInfo = renewalInfo,
        holderKey = keyMaterial.publicKey,
    )

    /**
     * Stores the credential of [prepared] only if its report is accepted, see [CredentialStorageResult]. A rejected
     * credential is a successful result without a stored entry; only persisting fails.
     */
    suspend fun storeAccepted(
        prepared: PreparedCredentialStorage,
    ): KmmResult<CredentialStorageResult> = catching {
        prepared.requireHolder()
        CredentialStorageResult(
            validation = prepared.validation,
            storedEntry = prepared.validation.credential?.let {
                subjectCredentialStore.storeCredential(
                    StoreEntry.fromPreparedCredential(prepared).getOrThrow()
                ).getOrThrow()
            })
    }

    /**
     * Stores the credential of [prepared] after the user has seen and accepted its report, also if it is rejected, as
     * long as only checks the policy may relax are not satisfied, i.e. its
     * [unacceptedCredential][at.asitplus.wallet.lib.validation.CredentialValidationResult.unacceptedCredential] is
     * present: its issuer may be untrusted, it may be expired or revoked, or miss required claims. Fails for a
     * credential that is not intact, e.g. with an invalid signature or bound to another key, which no user can accept.
     */
    suspend fun storeAfterUserConsent(
        prepared: PreparedCredentialStorage,
    ): KmmResult<CredentialStorageResult> = catching {
        prepared.requireHolder()
        prepared.validation.unacceptedCredential
            ?: throw prepared.validation.report.firstRejection()
                ?: IllegalArgumentException("The credential is not intact")
        CredentialStorageResult(
            validation = prepared.validation,
            storedEntry = subjectCredentialStore.storeCredential(
                StoreEntry.fromPreparedCredential(prepared).getOrThrow()
            ).getOrThrow()
        )
    }

    private fun PreparedCredentialStorage.requireHolder() = require(holderKey == keyMaterial.publicKey) {
        "The credential has been prepared for another holder"
    }

    private suspend fun validate(
        credential: Holder.StoreCredentialInput,
        policy: ValidationPolicy,
    ): CredentialValidationResult {
        val bound = policy.boundToHolder()
        return when (credential) {
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
    }

    private fun context(credentialIdentifier: String) = CredentialValidationContext(
        expectedHolderKey = keyMaterial.publicKey,
        expectedCredentialIdentifier = credentialIdentifier,
    )

    /** A credential to store is bound to the key of this holder, whatever [ValidationPolicy.holderBinding] says. */
    private fun ValidationPolicy.boundToHolder() = copy(holderBinding = HolderBindingPolicy.RequireExpectedKey)

    private fun CredentialScheme.credentialIdentifier(input: CredentialValidationInput): String = when (input) {
        is CredentialValidationInput.VcJwt -> vcType
        is CredentialValidationInput.SdJwtVc -> sdJwtType
        is CredentialValidationInput.IsoMdoc -> isoDocType
    } ?: throw IllegalArgumentException("Scheme $this does not support the representation of $input")

    /** The credential of [input] to store, from what its validation decoded, see [prepareCredentialStorage]. */
    private fun CredentialValidationInput.toStoreCredentialInput(
        validated: ValidatedCredential,
        scheme: CredentialScheme,
    ): Holder.StoreCredentialInput = when (this) {
        is CredentialValidationInput.VcJwt -> Holder.StoreCredentialInput.Vc(
            signedVcJws = JwsCompactTyped<VerifiableCredentialJws>(compact),
            vcJws = compact,
            scheme = scheme as VcJwtCredentialScheme,
        )

        is CredentialValidationInput.SdJwtVc -> Holder.StoreCredentialInput.SdJwt(
            signedSdJwtVc = (validated as ValidatedCredential.SdJwtVc).sdJwtSigned,
            vcSdJwt = compact,
            scheme = scheme as SdJwtCredentialScheme,
        )

        is CredentialValidationInput.IsoMdoc -> Holder.StoreCredentialInput.Iso(
            issuerSigned = (validated as ValidatedCredential.IsoMdoc).issuerSigned,
            scheme = scheme as IsoMdocCredentialScheme,
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
            orderingValidator.validate(input, orderingPolicy).report.checks
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
