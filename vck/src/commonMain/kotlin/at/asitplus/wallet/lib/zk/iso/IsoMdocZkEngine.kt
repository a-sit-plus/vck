package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.KeyMaterial
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.ZkMetadata
import kotlin.jvm.JvmOverloads

/**
 * Central engine for routing and coordinating ISO mDoc Zero-Knowledge (ZK) proof operations.
 *
 * For provers, this coordinates proof generation by evaluating requested systems against available backends.
 * For verifiers, this is the primary entry point to transform a [ZkDocument] into a
 * self-contained, verifiable [IsoMdocZkProof] object.
 *
 * @param registry The registry containing available [IsoMdocZkBackend]s. Defaults to [IsoMdocZkBackendRegistry.Default].
 * @param selectionStrategy The strategy used to pick a backend when multiple candidates are available.
 * Defaults to [SelectionStrategy.Default].
 */
class IsoMdocZkEngine @JvmOverloads constructor(
    private val registry: IsoMdocZkBackendRegistry = IsoMdocZkBackendRegistry.Default,
    private val selectionStrategy: SelectionStrategy = SelectionStrategy.Default
) {
    /**
     * Generates an [IsoMdocZkProof] based on the provided request and presentation parameters.
     *
     * This method acts as a routing coordinator. It extracts the requested ZK systems from the [isoParameters],
     * uses [IsoMdocZkBackend.supports] to filter compatible backends in the [registry], applies the
     * [selectionStrategy] to pick the most appropriate one, and delegates the heavy lifting of proof
     * generation (and final system selection) to that chosen backend.
     *
     * @param request The parameters of the presentation request.
     * @param isoParameters The ISO-specific presentation parameters, containing the credential and ZK metadata.
     * @param keyMaterial The key material used for holder binding purposes.
     * @return A [KmmResult] containing the generated [IsoMdocZkProof], or an error if no suitable backend is found
     * or generation fails.
     */
    suspend fun generate(
        request: PresentationRequestParameters,
        isoParameters: IsoPresentationParameters,
        keyMaterial: KeyMaterial,
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkMetadata = isoParameters.zkMetadata as? ZkMetadata.IsoMdocZk
            ?: throw IllegalArgumentException("ZK metadata incompatible with Iso mDoc")

        val supportedBackends = findSupportedBackends(zkMetadata.zkRequest.systemSpecs, registry.backends)
        val (selectedBackend, supportedSystems) = selectionStrategy.selectForGenerate(supportedBackends)
            ?: throw PresentationException("No backend found for specified ZK systems")

        selectedBackend.generate(
            request = request,
            credential = isoParameters.credential,
            requestedClaims = isoParameters.claims,
            zkSystemSpecs = supportedSystems,
            keyMaterial = keyMaterial,
        ).getOrThrow()
    }

    /**
     * Reconstructs an [IsoMdocZkProof] from a [ZkDocument].
     *
     * This method is intended to be used by the verifier to resolve the correct backend for an incoming document.
     * It ensures the document's system ID matches the expected [zkSystemSpec], delegates to the
     * appropriate backend to load the data, and returns a self-contained proof object.
     *
     * **Note:** This method only parses and loads the [ZkDocument] into a self-contained [IsoMdocZkProof].
     * The caller must subsequently invoke [IsoMdocZkProof.verify] on the returned instance to perform the actual
     * zero-knowledge proof verification.
     *
     * @param zkSystemSpec The ZK system specification expected for this document.
     * @param zkDocument The document containing the serialized proof data.
     * @param sessionTranscript The session transcript for binding verification.
     * @return A [KmmResult] containing the loaded [IsoMdocZkProof] ready for verification, or an error if
     * the system ID mismatches, no suitable backend is found, or deserialization fails.
     */
    fun load(
        zkSystemSpec: ZkSystemSpec,
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkSystemId = zkDocument.zkDocumentDataBytes.value.zkSystemId
        if (zkSystemId != zkSystemSpec.id)
            throw PresentationException(
                "ZKSystemId mismatch: Document specified $zkSystemId, but request specifies ${zkSystemSpec.id}"
            )

        val matchingBackends = registry.backends.filter { it.supports(zkSystemSpec) }
        val backend = selectionStrategy.selectForLoad(matchingBackends)
            ?: throw PresentationException("No backend found for ZK system: $zkSystemId")

        backend.load(zkDocument, sessionTranscript, zkSystemSpec).getOrThrow()
    }

    private fun findSupportedBackends(
        zkSystemSpecs: List<ZkSystemSpec>,
        backends: Set<IsoMdocZkBackend>
    ): Map<IsoMdocZkBackend, List<ZkSystemSpec>> = backends
        .associateWith { backend -> zkSystemSpecs.filter { backend.supports(it) } }
        .filterValues { it.isNotEmpty() }


    /**
     * Strategy to decide how backends are selected when multiple candidates match a request.
     */
    interface SelectionStrategy {
        /**
         * Used during generation to negotiate WHICH backend to use and WHICH subset
         * of the requested [ZkSystemSpec]s it will handle.
         * Returning `null` implies the strategy could not find a suitable candidate.
         */
        fun selectForGenerate(
            supportedBackends: Map<IsoMdocZkBackend, List<ZkSystemSpec>>
        ): Pair<IsoMdocZkBackend, List<ZkSystemSpec>>?

        /**
         * Used during load to tie-break when multiple backends support the exact same [ZkSystemSpec].
         * Returning `null` implies the strategy could not find a suitable candidate.
         */
        fun selectForLoad(candidates: List<IsoMdocZkBackend>): IsoMdocZkBackend?

        /**
         * The default selection strategy.
         *
         * - During generation: Picks the first backend that supports at least one requested ZK system.
         * - During load: Picks the first backend that supports the requested ZK system.
         */
        companion object Default : SelectionStrategy {
            override fun selectForGenerate(
                supportedBackends: Map<IsoMdocZkBackend, List<ZkSystemSpec>>
            ): Pair<IsoMdocZkBackend, List<ZkSystemSpec>>? =
                supportedBackends.entries.firstOrNull()?.toPair()

            override fun selectForLoad(candidates: List<IsoMdocZkBackend>): IsoMdocZkBackend? =
                candidates.firstOrNull()
        }
    }
}
