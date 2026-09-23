package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.openid.truncateToSeconds
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.cbor.CoseHeaderNone
import at.asitplus.wallet.lib.cbor.SignCoseDetached
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.serializer
import org.multipaz.mdoc.zkp.ZkSystemSpec as MultipazZkSystemSpec
import org.multipaz.mdoc.zkp.longfellow.LongfellowZkSystem
import kotlin.ByteArray
import kotlin.concurrent.Volatile
import kotlin.time.Clock

/**
 * An [IsoMdocZkBackend] implementation backed by the Longfellow-ZK zero-knowledge system
 * (via the Multipaz library).
 *
 * This class handles proof generation and verification for ISO/IEC 18013-5 mdoc credentials
 * using Longfellow-ZK circuits. It bridges internal domain models ([ZkSystemSpec], [ZkDocument],
 * [SessionTranscript]) to and from Multipaz-native data structures.
 *
 * **Lifecycle:**
 * Before invoking operations that rely on backend capabilities (e.g., [supports], [generate], [load]),
 * the backend MUST be initialized by calling [initialize].
 */
class LongfellowBackend : IsoMdocZkBackend {

    private class InitializedState(
        val backend: LongfellowZkSystem
    ) {
        val zkSystemSpecs: List<ZkSystemSpec> = backend.systemSpecs.map { it.toZkSystemSpec() }
        val supportedHashes: Set<String> = zkSystemSpecs.mapNotNull { it.params[CIRCUIT_HASH_KEY] as? String }.toSet()
    }

    private val initMutex = Mutex()
    @Volatile
    private var state: InitializedState? = null

    private val currentState: InitializedState
        get() = checkNotNull(state) { "LongfellowZkBackend is not initialized. Call initialize() first." }

    private fun createVerifyFn(
        zkSystemSpec: ZkSystemSpec,
        sessionTranscript: SessionTranscript,
        zkDocument: ZkDocument
    ): suspend () -> KmmResult<Unit> = {
        catching {
            currentState.backend.verifyProof(
                zkDocument = zkDocument.toMultipazZkDocument(),
                zkSystemSpec = zkSystemSpec.toMultipazZkSystemSpec(),
                sessionTranscript = sessionTranscript.toMultipazSessionTranscript(),
            )
        }
    }

    /**
     * The list of zero-knowledge system specifications available in this backend.
     *
     * @throws IllegalStateException if [initialize] has not been called.
     */
    override val zkSystemSpecs: List<ZkSystemSpec>
        get() = currentState.zkSystemSpecs

    /**
     * The identifier string of the underlying zero-knowledge engine (e.g., `"longfellow-libzk-v1"`).
     *
     * @throws IllegalStateException if [initialize] has not been called.
     */
    override val system: String
        get() = currentState.backend.name

    /**
     * Maps parameter key names to their expected kotlinx [KSerializer] instances
     * for serializing and deserializing zero-knowledge system specifications.
     */
    override val paramSerializers: Map<String, KSerializer<*>>
        get() = PARAM_SERIALIZERS

    /**
     * Determines whether the given [candidate] specification is supported by this backend.
     *
     * Support requires matching the backend [system] name and a known `circuit_hash`.
     * Other parameters (e.g., `num_attributes`) are ignored during lookup.
     *
     * @param candidate The [ZkSystemSpec] to evaluate for support.
     * @return `true` if supported; `false` otherwise.
     * @throws IllegalStateException if [initialize] has not been called.
     */
    override fun supports(candidate: ZkSystemSpec): Boolean =
        candidate.system == system && candidate.params[CIRCUIT_HASH_KEY] in currentState.supportedHashes

    private fun chooseZkSystemSpec(
        credential: StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        requestedZkSystemSpecs: List<ZkSystemSpec>,
    ): MultipazZkSystemSpec? {
        val multipazRequestedClaims = requestedClaims.map {
            it.toMdocRequestedClaim(credential.schemeIdentifier)
        }
        val multipazZkSystemSpecs: List<MultipazZkSystemSpec> = requestedZkSystemSpecs
            .filter(::supports)
            .map { it.toMultipazZkSystemSpec() }

        val matchedSpec = currentState.backend.getMatchingSystemSpec(
            multipazZkSystemSpecs,
            multipazRequestedClaims
        ) ?: return null

        val matchedHash = checkNotNull(matchedSpec.getParam<String>(CIRCUIT_HASH_KEY)) {
            "Backend matched spec is missing mandatory parameter: $CIRCUIT_HASH_KEY"
        }

        val exactMatch: MultipazZkSystemSpec? = multipazZkSystemSpecs.firstOrNull { candidate ->
            candidate.system == matchedSpec.system && candidate.params == matchedSpec.params
        }
        // Resolve final candidate (falling back to CIRCUIT_HASH_KEY if exact match fails)
        val matchedCandidate: MultipazZkSystemSpec = exactMatch ?: multipazZkSystemSpecs.firstOrNull { candidate ->
            candidate.getParam<String>(CIRCUIT_HASH_KEY) == matchedHash
        } ?: error("Backend matched spec returned an unknown $CIRCUIT_HASH_KEY: $matchedHash")

        return matchedSpec.copyWithParameters(id = matchedCandidate.id)
    }

    /**
     * Generates a zero-knowledge proof for a given credential and requested claim paths.
     *
     * @param request Presentation request parameters containing session context.
     * @param credential The ISO mdoc credential store entry containing attributes to disclose.
     * @param requestedClaims The set of normalized JSON paths representing requested claims.
     * @param requestedZkSystemSpecs Acceptable ZK system specifications requested by the verifier.
     * @param keyMaterial The key material used for signing device authentication in the mDoc context.
     * @return A [KmmResult] wrapping the generated [IsoMdocZkProof].
     * @throws IllegalStateException if [initialize] has not been called.
     */
    override suspend fun generate(
        request: PresentationRequestParameters,
        credential: StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        requestedZkSystemSpecs: List<ZkSystemSpec>,
        keyMaterial: KeyMaterial
    ): KmmResult<IsoMdocZkProof> = catching {
        val sessionTranscript = requireNotNull(request.calcIsoSessionTranscript()) {
            "calcIsoSessionTranscript not implemented"
        }
        val selectedMultipazZkSystemSpec = requireNotNull(
            chooseZkSystemSpec(credential, requestedClaims, requestedZkSystemSpecs)
        ) { "No matching ZK system spec found" }
        val selectedZkSystemSpec = selectedMultipazZkSystemSpec.toZkSystemSpec()

        val signDeviceAuthDetached = SignCoseDetached<ByteArray>(
            keyMaterial = keyMaterial,
            protectedHeaderModifier = CoseHeaderNone(),
            unprotectedHeaderModifier = CoseHeaderNone()
        )
        val plainMultipazDocument = credential
            .discloseRequestedClaims(requestedClaims, sessionTranscript, signDeviceAuthDetached)
            .toMultipazDocument()

        val zkDocument = currentState.backend.generateProof(
            zkSystemSpec = selectedMultipazZkSystemSpec,
            document = plainMultipazDocument,
            sessionTranscript = sessionTranscript.toMultipazSessionTranscript(),
            timestamp = Clock.System.now().truncateToSeconds(),
        ).toZkDocument()

        IsoMdocZkProof(
            zkDocument = zkDocument,
            verifyFn = createVerifyFn(selectedZkSystemSpec, sessionTranscript, zkDocument),
        )
    }

    /**
     * Constructs an [IsoMdocZkProof] handle from an existing [ZkDocument] for verification.
     *
     * @param zkDocument The received ISO mdoc ZkDocument.
     * @param sessionTranscript The ISO mdoc session transcript.
     * @param zkSystemSpec The specification matching the circuit used to generate the proof.
     * @return A [KmmResult] wrapping the executable [IsoMdocZkProof].
     * @throws IllegalArgumentException if [zkSystemSpec] is not supported by this backend.
     * @throws IllegalStateException if [initialize] has not been called.
     */
    override fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): KmmResult<IsoMdocZkProof> = catching {
        require(supports(zkSystemSpec)) {
            "LongfellowZkBackend cannot load this document, because it does not support spec: ${zkSystemSpec.id}"
        }
        IsoMdocZkProof(
            zkDocument = zkDocument,
            verifyFn = createVerifyFn(zkSystemSpec, sessionTranscript, zkDocument),
        )
    }

    /**
     * Initializes the Longfellow-ZK backend engine safely across coroutines.
     * Loads default circuits into memory. If already initialized, this operation is a no-op.
     *
     * @return A [KmmResult] wrapping [Unit] on success, or an exception on failure.
     */
    override suspend fun initialize(): KmmResult<Unit> = catching {
        if (state != null) return@catching

        initMutex.withLock {
            if (state == null) {
                state = InitializedState(
                    backend = LongfellowZkSystem().also { it.addDefaultCircuits() }
                )
            }
        }
    }

    companion object {

        internal const val VERSION_KEY = "version"
        internal const val CIRCUIT_HASH_KEY = "circuit_hash"
        internal const val NUM_ATTRIBUTES_KEY = "num_attributes"
        internal const val BLOCK_ENC_HASH_KEY = "block_enc_hash"
        internal const val BLOCK_ENC_SIG_KEY = "block_enc_sig"

        private val PARAM_SERIALIZERS: Map<String, KSerializer<*>> = mapOf(
            VERSION_KEY to Long.serializer(),
            CIRCUIT_HASH_KEY to String.serializer(),
            NUM_ATTRIBUTES_KEY to Long.serializer(),
            BLOCK_ENC_HASH_KEY to Long.serializer(),
            BLOCK_ENC_SIG_KEY to Long.serializer(),
        )

    }
}