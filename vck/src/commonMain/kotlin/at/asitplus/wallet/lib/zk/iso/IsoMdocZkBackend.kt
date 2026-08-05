package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystem
import at.asitplus.jsonpath.core.NormalizedJsonPath
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
     * It must match the `systemName` used in the [at.asitplus.iso.ZkSystem] specifications
     * for which this backend provides proofs.
     *
     * While multiple backends can share the same `systemName` (e.g. providing different implementations
     * for the same ZK system), their [paramSerializers] must be compatible.
     * See [at.asitplus.iso.ZkSystemParamRegistry.register] for details on compatibility and potential exceptions.
     */
    val systemName: String

    /**
     * A map of serializers for system-specific parameters used by this ZK system.
     *
     * These serializers are registered in [at.asitplus.iso.ZkSystemParamRegistry] during backend registration
     * to enable correct deserialization of [at.asitplus.iso.ZkSystem.params].
     */
    val paramSerializers: Map<String, KSerializer<*>>

    /**
     * Checks if this backend supports the specified [zkSystem].
     *
     * Supporting a system means being able to generate and verify proofs for the cryptographic
     * parameters and requirements defined in that [ZkSystem].
     */
    fun supports(zkSystem: ZkSystem): Boolean

    /**
     * Generates an [IsoMdocZkProof] for the given request and credential.
     *
     * @param request The parameters of the presentation request.
     * @param credential The ISO mDoc credential to prove statements about.
     * @param requestedClaims The set of claims (as JSON Paths) to be included/disclosed in the proof.
     * @param zkSystems The list of ZK systems requested by the verifier.
     * @return A [KmmResult] containing the generated [IsoMdocZkProof], or an error if generation fails.
     */
    suspend fun generate(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        zkSystems: List<ZkSystem>
    ): KmmResult<IsoMdocZkProof>

    /**
     * Loads an existing [IsoMdocZkProof] from its serialized form or raw data.
     *
     * This is typically used by a verifier or a holder re-constructing a proof from a [ZkDocument].
     *
     * @param zkDocument The document containing the proof data.
     * @param sessionTranscript The session transcript used to bind the proof to the current session.
     * @param zkSystem The ZK system specification relevant for this proof.
     */
    fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystem: ZkSystem
    ): IsoMdocZkProof

    /**
     * [initialize] tries to register a backend and returns Unit if successful and a throwable otherwise.
     * Repeated calls for an already successfully initialized backend MUST succeed.
     *
     * This method is called by [IsoMdocZkBackendRegistry.register] before adding the backend to the registry.
     */
    suspend fun initialize(): KmmResult<Unit>
}