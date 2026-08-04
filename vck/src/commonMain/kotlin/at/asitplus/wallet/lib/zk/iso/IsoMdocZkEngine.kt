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

class IsoMdocZkEngine(
    private val registry: IsoMdocZkBackendRegistry = IsoMdocZkBackendRegistry.Default,
    private val selectionStrategy: SelectionStrategy = SelectionStrategy.Default
) {
    suspend fun generate(
        request: PresentationRequestParameters,
        isoParameters: IsoPresentationParameters
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkMetadata = isoParameters.zkMetadata as? ZkMetadata.IsoMdocZk
            ?: throw IllegalArgumentException("ZK metadata incompatible with Iso mDoc!")

        val supportedBackends = findSupportedBackends(zkMetadata.zkInfo.systemSpecs, registry.backends)
        val (selectedBackend, supportedSystems) = selectionStrategy.selectForGenerate(supportedBackends)
            ?: throw PresentationException("No backend found for specified ZK systems!")

        selectedBackend.generate(
            request = request,
            credential = isoParameters.credential,
            requestedClaims = isoPresentationParametersToClaims(isoParameters),
            zkSystems = supportedSystems
        ).getOrThrow()
    }

    fun load(
        zkSystem: ZkSystem,
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkSystemId = zkDocument.zkDocumentDataBytes.value.zkSystemId
        if (zkSystemId != zkSystem.zkSystemId)
            throw PresentationException("ZKSystemId mismatch")

        val matchingBackends = registry.backends.filter { it.supports(zkSystem) }
        val backend = selectionStrategy.selectForLoad(matchingBackends)
            ?: throw PresentationException("No backend found for ZK system: $zkSystemId")

        backend.load(zkDocument, sessionTranscript, zkSystem)
    }

    private fun findSupportedBackends(
        zkSystems: List<ZkSystem>,
        backends: Set<IsoMdocZkBackend>
    ): Map<IsoMdocZkBackend, List<ZkSystem>> =
        backends
            .associateWith { backend -> zkSystems.filter { backend.supports(it) } }
            .filterValues { it.isNotEmpty() }

    private fun isoPresentationParametersToClaims(isoParameters: IsoPresentationParameters) =
        isoParameters.claims

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

        companion object Default : SelectionStrategy {
            override fun selectForGenerate(
                supportedBackends: Map<IsoMdocZkBackend, List<ZkSystem>>
            ): Pair<IsoMdocZkBackend, List<ZkSystem>>? =
                supportedBackends.entries.firstOrNull()?.toPair()

            override fun selectForLoad(candidates: List<IsoMdocZkBackend>): IsoMdocZkBackend? =
                candidates.firstOrNull()
        }
    }

    companion object {
        val Default = IsoMdocZkEngine()
    }
}
