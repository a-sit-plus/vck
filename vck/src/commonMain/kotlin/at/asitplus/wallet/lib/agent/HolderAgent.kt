package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.dif.FormatHolder
import at.asitplus.dif.InputDescriptor
import at.asitplus.iso.DeviceRequest
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.dcql.DCQLQuery
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.agent.validation.sdJwt.SdJwtInputValidator
import at.asitplus.wallet.lib.agent.validation.vcJws.VcJwsInputValidator
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import at.asitplus.wallet.lib.cbor.SignCoseDetachedFun
import at.asitplus.wallet.lib.data.CredentialPresentation
import at.asitplus.wallet.lib.data.CredentialPresentationRequest
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.KeyBindingJws
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.dif.PresentationExchangeInputEvaluator
import at.asitplus.wallet.lib.jws.JwsHeaderCertOrJwk
import at.asitplus.wallet.lib.jws.JwsHeaderNone
import at.asitplus.wallet.lib.jws.SignJwt
import at.asitplus.wallet.lib.jws.SignJwtFun
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.procedures.iso.DeviceRetrievalProcedure
import at.asitplus.wallet.lib.zk.iso.IsoMdocZkEngine
import io.github.aakira.napier.Napier
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.joinAll
import kotlin.jvm.JvmOverloads

/**
 * An agent that only implements [Holder], i.e. it can receive credentials from other agents
 * and present credentials to other agents.
 */
class HolderAgent @JvmOverloads constructor(
    override val keyMaterial: KeyMaterial,
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val validator: Validator = Validator(),
    /**
     * Certificates of the issuers we trust, e.g. extracted from an ETSI trust list. When set, credentials whose
     * issuer certificate is not signed by one of these are rejected on [storeCredential]. When null, issuer
     * signatures are only verified against the key the credential asserts itself, i.e. no trust decision is made.
     */
    trustedIssuers: TrustedCertificates? = null,
    private val validatorVcJws: ValidatorVcJws = ValidatorVcJws(
        vcJwsInputValidator = VcJwsInputValidator(verifyJwsObject = issuerJwsVerifier(trustedIssuers)),
        validator = validator,
    ),
    private val validatorSdJwt: ValidatorSdJwt = ValidatorSdJwt(
        sdJwtInputValidator = SdJwtInputValidator(verifyJwsObject = issuerJwsVerifier(trustedIssuers)),
        validator = validator,
    ),
    private val validatorMdoc: ValidatorMdoc = ValidatorMdoc(
        verifyCoseSignature = issuerCoseVerifier(trustedIssuers),
        validator = validator,
    ),
    private val signVerifiablePresentation: SignJwtFun<VerifiablePresentationJws> =
        SignJwt(keyMaterial, JwsHeaderCertOrJwk()),
    private val signKeyBinding: SignJwtFun<KeyBindingJws> = SignJwt(keyMaterial, JwsHeaderNone()),
    private val signDeviceAuthDetached: SignCoseDetachedFun<ByteArray> = SignCoseDetached(
        keyMaterial = keyMaterial,
        protectedHeaderModifier = CoseHeaderNone(),
        unprotectedHeaderModifier = CoseHeaderNone()
    ),
    private val mdocZkEngine: IsoMdocZkEngine = IsoMdocZkEngine(),
    private val verifiablePresentationFactory: VerifiablePresentationFactory =
        VerifiablePresentationFactory(
            keyMaterial = keyMaterial,
            signVerifiablePresentation = signVerifiablePresentation,
            signKeyBinding = signKeyBinding,
            mdocZkEngine = mdocZkEngine,
            signDeviceAuthDetached = signDeviceAuthDetached
        ),
    private val difInputEvaluator: PresentationExchangeInputEvaluator = PresentationExchangeInputEvaluator,
) : Holder {

    private val presentationResponseCreator = PresentationResponseCreator(verifiablePresentationFactory)

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     */
    override suspend fun storeCredential(
        credential: Holder.StoreCredentialInput,
        renewalInfo: CredentialRenewalInfo?
    ) = catching {
        when (credential) {
            is Holder.StoreCredentialInput.Vc -> {
                val validated = validatorVcJws.verifyVcJws(credential.signedVcJws, keyMaterial.publicKey).getOrThrow()
                subjectCredentialStore.storeCredential(
                    vc = validated.jws,
                    vcSerialized = credential.vcJws,
                    scheme = credential.scheme,
                    renewalInfo = renewalInfo,
                    issuer = credential.signedVcJws.jws.jwsHeader.certificateChain?.leaf
                )
            }

            is Holder.StoreCredentialInput.SdJwt -> {
                if (credential.signedSdJwtVc.keyBindingJws != null) {
                    throw Throwable("Issued SD-JWT credentials must not contain a KB")
                }
                val validated = validatorSdJwt.verifySdJwt(credential.signedSdJwtVc, keyMaterial.publicKey).getOrThrow()
                subjectCredentialStore.storeCredential(
                    vc = validated.verifiableCredentialSdJwt,
                    vcSerialized = credential.vcSdJwt,
                    disclosures = validated.disclosures,
                    scheme = credential.scheme,
                    renewalInfo = renewalInfo,
                    issuer = credential.signedSdJwtVc.jws.jwsHeader.certificateChain?.leaf
                )
            }

            is Holder.StoreCredentialInput.Iso -> {
                val validated = validatorMdoc.verifyIsoCred(credential.issuerSigned).getOrThrow()
                subjectCredentialStore.storeCredential(
                    issuerSigned = validated.issuerSigned,
                    scheme = credential.scheme,
                    renewalInfo = renewalInfo,
                    issuer = credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain?.getOrNull(0)
                        ?.let { X509Certificate.decodeFromDer(it) }
                )
            }
        }
    }



    /**
     * Gets a list of all stored credentials, with a revocation status.
     */
    override suspend fun getCredentials(): Collection<StoreEntry>? =
        subjectCredentialStore.getCredentials().getOrNull()

    /** Gets a list of all valid stored credentials sorted by preference, possibly filtered by [filterByIds]. */
    private suspend fun getValidCredentialsByPriority(filterByIds: Collection<String>? = null): List<StoreEntry>? {
        val availableCredentials = getCredentials() ?: return null

        val presortedCredentials = availableCredentials
            .filter { filterByIds == null || filterByIds.contains(it.getDcApiId()) }
            .sortedBy { it.sortKey() }

        val withRevocationStatusQueryIssued = presortedCredentials.map {
            it to coroutineScope {
                async {
                    validator.checkCredentialFreshness(it)
                }
            }
        }
        withRevocationStatusQueryIssued.map { it.second }.joinAll()
        val withRevocationStatusAvailable = withRevocationStatusQueryIssued.map {
            it.first to it.second.await()
        }
        return withRevocationStatusAvailable.sortedBy {
            if (it.second.isFresh) 0 else 1
        }.map { it.first }
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
    @Suppress("DEPRECATION")
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

            is CredentialPresentationRequest.PresentationExchangeRequest -> PresentationExchangeMatchingResult(
                presentationRequest = presentationRequest,
                matchingResult = matchInputDescriptorsAgainstCredentialStoreV2(
                    inputDescriptors = presentationRequest.presentationDefinition.inputDescriptors,
                    fallbackFormatHolder = presentationRequest.fallbackFormatHolder,
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

    @Suppress("DEPRECATION")
    override suspend fun createPresentation(
        request: PresentationRequestParameters,
        credentialPresentation: CredentialPresentation,
    ): KmmResult<PresentationResponseParameters> = presentationResponseCreator.create(
        request = request,
        credentialPresentation = credentialPresentation,
        matchDCQLQuery = { matchDCQLQueryAgainstCredentialStoreV2(it) },
        matchDeviceRequest = { matchDeviceRetrievalAgainstCredentialStore(it) },
        matchPresentationExchange = suspend {
            matchInputDescriptorsAgainstCredentialStoreV2(
                it.presentationDefinition.inputDescriptors,
                it.fallbackFormatHolder,
            )
        },
    )

    @Deprecated("Use matchPresentationRequestAgainstCredentialStore instead")
    override suspend fun matchInputDescriptorsAgainstCredentialStoreV2(
        inputDescriptors: Collection<InputDescriptor>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
        filterByIds: Collection<String>?,
    ) = catching {
        findInputDescriptorMatches(
            inputDescriptors = inputDescriptors,
            credentials = getValidCredentialsByPriority(filterByIds = filterByIds)
                ?: throw PresentationException("Credentials could not be retrieved from the store"),
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }

    private fun findInputDescriptorMatches(
        inputDescriptors: Collection<InputDescriptor>,
        credentials: List<StoreEntry>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: PathAuthorizationValidator?,
    ) = HolderPresentationExchangeQueryMatchingResult(
        credentials = credentials,
        queryMatchingResult = PresentationExchangeQueryMatchingResult(
            inputDescriptors.associateWith { inputDescriptor ->
                credentials.map { credential ->
                    difInputEvaluator.evaluateInputDescriptorAgainstCredential(
                        inputDescriptor = inputDescriptor,
                        fallbackFormatHolder = fallbackFormatHolder,
                        credentialClaimStructure = CredentialToJsonConverter.toJsonElement(credential),
                        credentialFormat = credential.credentialFormat,
                        credentialScheme = credential.schemeIdentifier,
                        pathAuthorizationValidator = {
                            pathAuthorizationValidator?.invoke(credential, it) ?: true
                        },
                    ).onFailure {
                        Napier.d("findInputDescriptorMatches failed for credential $credential", it)
                    }
                }
            }.mapKeys {
                it.key.id
            },
        )
    )

    @Deprecated(
        "Use matchPresentationRequestAgainstCredentialStore instead",
        ReplaceWith(
            "matchPresentationRequestAgainstCredentialStore(CredentialPresentationRequest.IsoDeviceRetrieval(deviceRequest), filterByIds)",
            "at.asitplus.wallet.lib.data.CredentialPresentationRequest",
        ),
    )
    override suspend fun matchDeviceRetrievalAgainstCredentialStore(
        deviceRequest: DeviceRequest,
        filterByIds: Collection<String>?
    ): KmmResult<HolderIsoDeviceRetrievalQueryMatchingResult<StoreEntry>> = catching {
        val credentials = getValidCredentialsByPriority(filterByIds)
            ?: throw PresentationException("Credentials could not be retrieved from the store")
        HolderIsoDeviceRetrievalQueryMatchingResult(
            credentials = credentials,
            queryMatchingResult = DeviceRetrievalProcedure.match(deviceRequest, credentials),
        )
    }

    @Deprecated("Use matchPresentationRequestAgainstCredentialStore instead")
    override fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: StoreEntry,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ) = difInputEvaluator.evaluateInputDescriptorAgainstCredential(
        inputDescriptor = inputDescriptor,
        fallbackFormatHolder = fallbackFormatHolder,
        credentialClaimStructure = CredentialToJsonConverter.toJsonElement(credential),
        credentialFormat = credential.credentialFormat,
        credentialScheme = credential.schemeIdentifier,
        pathAuthorizationValidator = pathAuthorizationValidator,
    )

    @Deprecated(
        "Use matchPresentationRequestAgainstCredentialStore instead",
        ReplaceWith(
            "matchPresentationRequestAgainstCredentialStore(CredentialPresentationRequest.DCQLRequest(dcqlQuery), filterByIds)",
            "at.asitplus.wallet.lib.data.CredentialPresentationRequest",
        ),
    )
    override suspend fun matchDCQLQueryAgainstCredentialStoreV2(
        dcqlQuery: DCQLQuery,
        filterByIds: Collection<String>?,
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
