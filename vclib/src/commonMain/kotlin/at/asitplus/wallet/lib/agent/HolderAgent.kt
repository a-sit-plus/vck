package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catching
import at.asitplus.crypto.datatypes.cose.CoseKey
import at.asitplus.crypto.datatypes.cose.toCoseKey
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.cbor.CoseService
import at.asitplus.wallet.lib.cbor.DefaultCoseService
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import at.asitplus.wallet.lib.data.dif.ClaimFormatEnum
import at.asitplus.wallet.lib.data.dif.FieldQueryResults
import at.asitplus.wallet.lib.data.dif.FormatHolder
import at.asitplus.wallet.lib.data.dif.InputDescriptor
import at.asitplus.wallet.lib.data.dif.InputEvaluator
import at.asitplus.wallet.lib.data.dif.PresentationDefinition
import at.asitplus.wallet.lib.data.dif.PresentationSubmission
import at.asitplus.wallet.lib.data.dif.PresentationSubmissionDescriptor
import at.asitplus.wallet.lib.jws.DefaultJwsService
import at.asitplus.wallet.lib.jws.JwsService
import com.benasher44.uuid.uuid4
import io.github.aakira.napier.Napier


/**
 * An agent that only implements [Holder], i.e. it can receive credentials form other agents
 * and present credentials to other agents.
 */
class HolderAgent(
    private val validator: Validator = Validator.newDefaultInstance(),
    private val subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore(),
    private val jwsService: JwsService,
    private val coseService: CoseService,
    override val keyPair: KeyPairAdapter,
    private val verifiablePresentationFactory: VerifiablePresentationFactory = VerifiablePresentationFactory(
        jwsService = jwsService,
        coseService = coseService,
        identifier = keyPair.identifier,
    ),
    private val difInputEvaluator: InputEvaluator = InputEvaluator(),
    override val defaultPathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean = { _, _ -> true }
) : Holder {

    constructor(
        keyPairAdapter: KeyPairAdapter,
        subjectCredentialStore: SubjectCredentialStore = InMemorySubjectCredentialStore()
    ) : this(
        validator = Validator.newDefaultInstance(DefaultVerifierCryptoService(), Parser()),
        subjectCredentialStore = subjectCredentialStore,
        jwsService = DefaultJwsService(DefaultCryptoService(keyPairAdapter)),
        coseService = DefaultCoseService(DefaultCryptoService(keyPairAdapter)),
        keyPair = keyPairAdapter
    )

    /**
     * Sets the revocation list ot use for further processing of Verifiable Credentials
     *
     * @return `true` if the revocation list has been validated and set, `false` otherwise
     */
    override fun setRevocationList(it: String): Boolean {
        return validator.setRevocationList(it)
    }

    /**
     * Stores the verifiable credential in [credential] if it parses and validates,
     * and returns it for future reference.
     *
     * Note: Revocation credentials should not be stored, but set with [setRevocationList].
     */
    override suspend fun storeCredential(credential: Holder.StoreCredentialInput)
            : KmmResult<Holder.StoredCredential> = catching {
        when (credential) {
            is Holder.StoreCredentialInput.Vc -> {
                val vc = validator.verifyVcJws(credential.vcJws, keyPair.publicKey)
                if (vc !is Verifier.VerifyCredentialResult.SuccessJwt) {
                    throw VerificationError(vc.toString())
                }
                subjectCredentialStore.storeCredential(vc.jws, credential.vcJws, credential.scheme)
                    .toStoredCredential()
            }

            is Holder.StoreCredentialInput.SdJwt -> {
                val sdJwt = validator.verifySdJwt(credential.vcSdJwt, keyPair.publicKey)
                if (sdJwt !is Verifier.VerifyCredentialResult.SuccessSdJwt) {
                    throw VerificationError(sdJwt.toString())
                }
                subjectCredentialStore.storeCredential(
                    sdJwt.sdJwt,
                    credential.vcSdJwt,
                    sdJwt.disclosures,
                    credential.scheme
                ).toStoredCredential()
            }

            is Holder.StoreCredentialInput.Iso -> {
                val issuerKey: CoseKey? = credential.issuerSigned.issuerAuth.unprotectedHeader?.certificateChain
                    ?.let {
                        runCatching { X509Certificate.decodeFromDer(it) }.getOrNull()
                            ?.publicKey?.toCoseKey()?.getOrNull()
                    }
                val iso = validator.verifyIsoCred(credential.issuerSigned, issuerKey)
                if (iso !is Verifier.VerifyCredentialResult.SuccessIso) {
                    throw VerificationError(iso.toString())
                }
                subjectCredentialStore.storeCredential(iso.issuerSigned, credential.scheme)
                    .toStoredCredential()
            }
        }
    }


    /**
     * Gets a list of all stored credentials, with a revocation status.
     *
     * Note that the revocation status may be [Validator.RevocationStatus.UNKNOWN] if no revocation list
     * has been set with [setRevocationList]
     */
    override suspend fun getCredentials(): Collection<Holder.StoredCredential>? {
        val credentials = subjectCredentialStore.getCredentials().getOrNull()
            ?: return null
                .also { Napier.w("Got no credentials from subjectCredentialStore") }
        return credentials.map { it.toStoredCredential() }
    }

    private fun SubjectCredentialStore.StoreEntry.toStoredCredential() = when (this) {
        is SubjectCredentialStore.StoreEntry.Iso ->
            Holder.StoredCredential.Iso(this, Validator.RevocationStatus.UNKNOWN)

        is SubjectCredentialStore.StoreEntry.Vc ->
            Holder.StoredCredential.Vc(this, validator.checkRevocationStatus(vc))

        is SubjectCredentialStore.StoreEntry.SdJwt ->
            Holder.StoredCredential.SdJwt(this, validator.checkRevocationStatus(sdJwt))
    }

    /**
     * Gets a list of all valid stored credentials sorted by preference
     */
    private suspend fun getValidCredentialsByPriority() = getCredentials()?.filter {
        it.status != Validator.RevocationStatus.REVOKED
    }?.map { it.storeEntry }?.sortedBy {
        // prefer iso credentials and sd jwt credentials over plain vc credentials
        // -> they support selective disclosure!
        when (it) {
            is SubjectCredentialStore.StoreEntry.Vc -> 2
            is SubjectCredentialStore.StoreEntry.SdJwt -> 1
            is SubjectCredentialStore.StoreEntry.Iso -> 1
        }
    }

    data class CandidateInputMatchContainer(
        val credential: SubjectCredentialStore.StoreEntry,
        val fieldQueryResults: FieldQueryResults,
    )

    override suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean,
    ): KmmResult<Holder.PresentationResponseParameters> = runCatching {
        val matches = matchInputDescriptorsAgainstCredentialStore(
            presentationDefinition = presentationDefinition,
            fallbackFormatHolder = fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrThrow().mapNotNull { (key, value) ->
            // TODO: support submission requirements, where not all input descriptors may have a match
            //  -> no need to throw at this point
            value?.let { key to it }
                ?: throw MissingInputDescriptorMatchException(key)
        }

        createPresentation(
            challenge = challenge,
            audienceId = audienceId,
            presentationDefinitionId = presentationDefinition.id,
            inputDescriptorMatches = matches,
        ).getOrThrow()
    }.wrap()

    suspend fun createPresentation(
        challenge: String,
        audienceId: String,
        presentationDefinitionId: String?,
        inputDescriptorMatches: List<Pair<InputDescriptor, CandidateInputMatchContainer>>,
    ): KmmResult<Holder.PresentationResponseParameters> = runCatching {
        val presentationSubmission = PresentationSubmission.fromMatches(
            presentationId = presentationDefinitionId,
            matches = inputDescriptorMatches,
        )

        val verifiablePresentations = inputDescriptorMatches.map { match ->
            val credential = match.second.credential
            val fieldQueryResults = match.second.fieldQueryResults
            verifiablePresentationFactory.createVerifiablePresentation(
                challenge = challenge,
                audienceId = audienceId,
                credential = credential,
                fieldQueryResults = fieldQueryResults,
            ) ?: throw CredentialPresentationException(
                credential = credential,
                inputDescriptor = match.first,
                fieldQueryResults = fieldQueryResults,
            )
        }

        Holder.PresentationResponseParameters(
            presentationSubmission = presentationSubmission,
            presentationResults = verifiablePresentations,
        )
    }.wrap()

    suspend fun createVcPresentation(
        validCredentials: List<String>,
        challenge: String,
        audienceId: String
    ) = verifiablePresentationFactory.createVcPresentation(
        validCredentials = validCredentials,
        challenge = challenge,
        audienceId = audienceId,
    )

    override suspend fun matchInputDescriptorsAgainstCredentialStore(
        presentationDefinition: PresentationDefinition,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean,
    ): KmmResult<Map<InputDescriptor, CandidateInputMatchContainer?>> = runCatching {
        findInputDescriptorMatches(
            inputDescriptors = presentationDefinition.inputDescriptors,
            credentials = getValidCredentialsByPriority() ?: throw CredentialRetrievalException(),
            fallbackFormatHolder = presentationDefinition.formats ?: fallbackFormatHolder,
            pathAuthorizationValidator = pathAuthorizationValidator,
        )
    }.wrap()

    private fun findInputDescriptorMatches(
        inputDescriptors: Collection<InputDescriptor>,
        credentials: Collection<SubjectCredentialStore.StoreEntry>,
        fallbackFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (SubjectCredentialStore.StoreEntry, NormalizedJsonPath) -> Boolean,
    ) = inputDescriptors.associateWith { inputDescriptor ->
        credentials.firstNotNullOfOrNull { credential ->
            evaluateInputDescriptorAgainstCredential(
                inputDescriptor = inputDescriptor,
                credential = credential,
                presentationDefinitionFormatHolder = fallbackFormatHolder,
                pathAuthorizationValidator = {
                    pathAuthorizationValidator(credential, it)
                },
            )?.let {
                CandidateInputMatchContainer(
                    credential = credential,
                    fieldQueryResults = it,
                )
            }
        }
    }

    private fun evaluateInputDescriptorAgainstCredential(
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry,
        presentationDefinitionFormatHolder: FormatHolder?,
        pathAuthorizationValidator: (NormalizedJsonPath) -> Boolean,
    ) = listOf(credential).filter {
        it.isFormatSupported(inputDescriptor.format ?: presentationDefinitionFormatHolder)
    }.filter {
        // iso credentials now have their doctype encoded into the id
        when (it) {
            is SubjectCredentialStore.StoreEntry.Iso -> it.scheme.isoDocType == inputDescriptor.id
            else -> true
        }
    }.firstNotNullOfOrNull {
        difInputEvaluator.evaluateFieldQueryResults(
            inputDescriptor = inputDescriptor,
            credential = CredentialToJsonConverter.toJsonElement(it),
            pathAuthorizationValidator = pathAuthorizationValidator,
        ).getOrNull()
    }

    /** assume credential format to be supported by the verifier if no format holder is specified */
    private fun SubjectCredentialStore.StoreEntry.isFormatSupported(supportedFormats: FormatHolder?): Boolean =
        supportedFormats?.let { formatHolder ->
            when (this) {
                is SubjectCredentialStore.StoreEntry.Vc -> formatHolder.jwtVp != null
                is SubjectCredentialStore.StoreEntry.SdJwt -> formatHolder.jwtSd != null
                is SubjectCredentialStore.StoreEntry.Iso -> formatHolder.msoMdoc != null
            }
        } ?: true

    private fun PresentationSubmission.Companion.fromMatches(
        presentationId: String?,
        matches: List<Pair<InputDescriptor, CandidateInputMatchContainer>>,
    ) = PresentationSubmission(
        id = uuid4().toString(),
        definitionId = presentationId,
        descriptorMap = matches.mapIndexed { index, match ->
            PresentationSubmissionDescriptor.fromMatch(
                inputDescriptor = match.first,
                credential = match.second.credential,
                index = if (matches.size == 1) null else index
            )
        }
    )

    private fun PresentationSubmissionDescriptor.Companion.fromMatch(
        inputDescriptor: InputDescriptor,
        credential: SubjectCredentialStore.StoreEntry,
        index: Int?
    ) = PresentationSubmissionDescriptor(
        id = inputDescriptor.id,
        format = when (credential) {
            is SubjectCredentialStore.StoreEntry.Vc -> ClaimFormatEnum.JWT_VP
            is SubjectCredentialStore.StoreEntry.SdJwt -> ClaimFormatEnum.JWT_SD
            is SubjectCredentialStore.StoreEntry.Iso -> ClaimFormatEnum.MSO_MDOC
        },
        // from https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1-2.4
        // These objects contain a field called path, which, for this specification,
        // MUST have the value $ (top level root path) when only one Verifiable Presentation is contained in the VP Token,
        // and MUST have the value $[n] (indexed path from root) when there are multiple Verifiable Presentations,
        // where n is the index to select.
        path = index?.let { "\$[$it]" } ?: "\$"
    )
}

open class PresentationException(message: String) : Exception(message)

class CredentialRetrievalException :
    PresentationException("Credentials could not be retrieved from the store")

class MissingInputDescriptorMatchException(
    val inputDescriptor: InputDescriptor,
) : PresentationException("No match was found for input descriptor $inputDescriptor")

class AttributeNotAvailableException(
    val credential: SubjectCredentialStore.StoreEntry.Iso,
    val namespace: String,
    val attributeName: String,
) : PresentationException("Attribute not available in credential: $['$namespace']['$attributeName']: $credential")

class CredentialPresentationException(
    val inputDescriptor: InputDescriptor,
    val credential: SubjectCredentialStore.StoreEntry,
    val fieldQueryResults: FieldQueryResults,
) : PresentationException("Presentation of $inputDescriptor failed with credential $credential and field query results: $fieldQueryResults")
