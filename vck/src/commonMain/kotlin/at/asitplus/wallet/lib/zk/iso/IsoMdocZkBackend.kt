package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.KSerializer

/**
 * Interface for generating and loading ISO mDoc Zero-Knowledge (ZK) proofs.
 *
 * Each implementation represents a specific ZK proof system.
 * Implementations must be registered with an [IsoMdocZkBackendRegistry] (typically [IsoMdocZkBackendRegistry.Default])
 * to be used during presentation generation.
 *
 * @see IsoMdocZkBackendRegistry
 * @see at.asitplus.iso.ZkSystemParamRegistry
 */
interface IsoMdocZkBackend {
    /**
     * Uniquely identifies the ZK proof system supported by this backend.
     *
     * This name is used to register and look up parameter serializers in [at.asitplus.iso.ZkSystemParamRegistry].
     * It must match the `systemName` used in the [at.asitplus.iso.ZkSystemSpec] specifications
     * for which this backend provides proofs.
     *
     * While multiple backends can share the same `systemName` (e.g. providing different implementations
     * for the same ZK system), their [paramSerializers] must be compatible.
     * See [at.asitplus.iso.ZkSystemParamRegistry.register] for details on compatibility and potential exceptions.
     */
    val system: String

    /**
     * A list of supported [ZkSystemSpec]s.
     *
     * This list should mainly be used by Verifiers to advertise support for specific [ZkSystemSpec]s to Provers.
     */
    val zkSystemSpecs: List<ZkSystemSpec>

    /**
     * A map of serializers for system-specific parameters used by this ZK system.
     *
     * These serializers are registered in [at.asitplus.iso.ZkSystemParamRegistry] during backend registration
     * to enable correct deserialization of [at.asitplus.iso.ZkSystemSpec.params].
     */
    val paramSerializers: Map<String, KSerializer<*>>

    /**
     * Checks whether this backend supports the specified [candidate].
     *
     * This method acts as a lightweight pre-selection mechanism for multi-backend architectures.
     * By evaluating compatibility upfront, callers can make smarter routing decisions and avoid
     * invoking the resource-intensive [generate] method on inherently incompatible backends.
     *
     * Supporting a system means the backend is capable of generating and verifying proofs
     * that fulfill the requirements and parameters defined by the [candidate].
     *
     * The default implementation returns `true` if at least one of the backend's [zkSystemSpecs] matches:
     * - The candidate's system identifier (`system`), and
     * - All parameters (`params`) provided by the candidate.
     *
     * @param candidate The [ZkSystemSpec] instance to evaluate.
     * @return `true` if the system is supported, `false` otherwise.
     */
    fun supports(candidate: ZkSystemSpec): Boolean {
        return zkSystemSpecs.any { supportedSpec ->
            supportedSpec.system == candidate.system && candidate.params.all { (key, userValue) ->
                supportedSpec.params[key] == userValue
            }
        }
    }

    /**
     * Generates an [IsoMdocZkProof] using this backend.
     *
     * This method evaluates the provided list of requested [zkSystemSpecs] and automatically
     * selects the most appropriate system that fits the presentation request. If none of the
     * provided specifications are supported by this backend, the operation will return an error.
     *
     * **Hint:** While this method handles system selection internally, callers operating in a
     * multi-backend environment may want to pre-evaluate backends using [supports]. Doing so
     * helps route the request to the most adequate backend upfront, potentially bypassing
     * unnecessary setup or calculation time.
     *
     * @param request The parameters of the presentation request.
     * @param credential The ISO mDoc credential to prove statements about.
     * @param requestedClaims The set of claims (as JSON Paths) to be disclosed in the proof.
     * @param zkSystemSpecs The list of ZK systems requested by the verifier to evaluate.
     * @param keyMaterial Key material used for holder binding purposes.
     * @return A [KmmResult] containing the generated [IsoMdocZkProof] on success, or an error if
     * no provided system specs are supported or generation fails.
     */
    suspend fun generate(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        zkSystemSpecs: List<ZkSystemSpec>,
        keyMaterial: KeyMaterial,
    ): KmmResult<IsoMdocZkProof>

    /**
     * Reconstructs a self-contained and verifiable [IsoMdocZkProof] from a [ZkDocument].
     *
     * This method is intended to be used by a verifier to load received proof data into
     * an object that can verify itself directly via [IsoMdocZkProof.verify].
     *
     * @param zkDocument The document containing the proof data.
     * @param sessionTranscript The session transcript used to bind the proof to the current session.
     * @param zkSystemSpec The ZK system specification relevant for this proof.
     * @return The loaded [IsoMdocZkProof] instance with embedded verification logic.
     */
    fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): KmmResult<IsoMdocZkProof>

    /**
     * attempts to register a backend and returns [Unit] if successful and a [Throwable] otherwise.
     * Repeated calls for an already successfully initialized backend MUST succeed.
     *
     * The backend must be initialized before any of its members can be used.
     *
     * This method is called by [IsoMdocZkBackendRegistry.register] before adding the backend to the registry.
     */
    suspend fun initialize(): KmmResult<Unit>
}