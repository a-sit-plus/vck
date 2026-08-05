package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystem
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.ZkMetadata
import kotlin.jvm.JvmOverloads

/**
 * Central engine for handling ISO mDoc Zero-Knowledge (ZK) proof operations.
 *
 * This engine coordinates between the [IsoMdocZkBackendRegistry] and a [SelectionStrategy] to
 * generate and load [IsoMdocZkProof]s.
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
     * This method extracts ZK metadata from the [isoParameters], finds backends in the [registry]
     * that support the requested ZK systems, uses the [selectionStrategy] to select a backend,
     * and delegates proof generation.
     *
     * @param request The parameters of the presentation request.
     * @param isoParameters The ISO-specific presentation parameters, containing the credential and ZK metadata.
     * @return A [KmmResult] containing the generated [IsoMdocZkProof], or an error if no suitable backend is found
     * or generation fails.
     */
    suspend fun generate(
        request: PresentationRequestParameters,
        isoParameters: IsoPresentationParameters
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkMetadata = isoParameters.zkMetadata as? ZkMetadata.IsoMdocZk
            ?: throw IllegalArgumentException("ZK metadata incompatible with Iso mDoc")

        val supportedBackends = findSupportedBackends(zkMetadata.zkInfo.systemSpecs, registry.backends)
        val (selectedBackend, supportedSystems) = selectionStrategy.selectForGenerate(supportedBackends)
            ?: throw PresentationException("No backend found for specified ZK systems")

        selectedBackend.generate(
            request = request,
            credential = isoParameters.credential,
            requestedClaims = isoParameters.claims,
            zkSystems = supportedSystems
        ).getOrThrow()
    }

    /**
     * Loads and validates an [IsoMdocZkProof] from a [ZkDocument].
     *
     * This method verifies that the [ZkSystem] ID in the document matches the requested [zkSystem],
     * finds backends in the [registry] that support the system, uses the [selectionStrategy]
     * to pick a backend, and delegates proof loading.
     *
     * @param zkSystem The ZK system specification expected for this document.
     * @param zkDocument The document containing the serialized proof data.
     * @param sessionTranscript The session transcript for binding verification.
     * @return A [KmmResult] containing the loaded [IsoMdocZkProof], or an error if the system ID mismatches,
     * no suitable backend is found, or loading fails.
     */
    fun load(
        zkSystem: ZkSystem,
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkSystemId = zkDocument.zkDocumentDataBytes.value.zkSystemId
        if (zkSystemId != zkSystem.zkSystemId)
            throw PresentationException(
                "ZKSystemId mismatch: Document specified $zkSystemId, but request specifies ${zkSystem.zkSystemId}"
            )

        val matchingBackends = registry.backends.filter { it.supports(zkSystem) }
        val backend = selectionStrategy.selectForLoad(matchingBackends)
            ?: throw PresentationException("No backend found for ZK system: $zkSystemId")

        backend.load(zkDocument, sessionTranscript, zkSystem)
    }

    private fun findSupportedBackends(
        zkSystems: List<ZkSystem>,
        backends: Set<IsoMdocZkBackend>
    ): Map<IsoMdocZkBackend, List<ZkSystem>> = backends
        .associateWith { backend -> zkSystems.filter { backend.supports(it) } }
        .filterValues { it.isNotEmpty() }


    /**
     * Strategy to decide how backends are selected when multiple candidates match a request.
     */
    interface SelectionStrategy {
        /**
         * Used during generation to negotiate WHICH backend to use and WHICH subset
         * of the requested [ZkSystem]s it will handle.
         * Returning `null` implies the strategy could not find a suitable candidate.
         */
        fun selectForGenerate(
            supportedBackends: Map<IsoMdocZkBackend, List<ZkSystem>>
        ): Pair<IsoMdocZkBackend, List<ZkSystem>>?

        /**
         * Used during load to tie-break when multiple backends support the exact same [ZkSystem].
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
                supportedBackends: Map<IsoMdocZkBackend, List<ZkSystem>>
            ): Pair<IsoMdocZkBackend, List<ZkSystem>>? =
                supportedBackends.entries.firstOrNull()?.toPair()

            override fun selectForLoad(candidates: List<IsoMdocZkBackend>): IsoMdocZkBackend? =
                candidates.firstOrNull()
        }
    }
}
