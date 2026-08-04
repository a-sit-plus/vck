package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystem
import at.asitplus.iso.ZkSystemParamRegistry
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.ZkMetadata
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

@OptIn(ExperimentalAtomicApi::class)
class IsoMdocZkBackendRegistry(
    private val selectionStrategy: SelectionStrategy = SelectionStrategy.Default
) {
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

    private val backends = AtomicReference<Set<IsoMdocZkBackend>>(emptySet())

    /**
     * Use [register] in your application to register backends for [IsoMdocZkBackend].
     * Ensures the backend is successfully initialized and its parameters are registered
     * before committing it to the available pool.
     */
    fun register(backend: IsoMdocZkBackend): KmmResult<Unit> = catching {
        backend.initialize().getOrThrow()
        ZkSystemParamRegistry.register(backend.systemName, backend.paramSerializers)
        backends.update { it + backend }
    }

    /**
     * Generates a verifiable [IsoMdocZkProof] using the specified or default selection strategy.
     */
    suspend fun generate(
        request: PresentationRequestParameters,
        isoParameters: IsoPresentationParameters,
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkMetadata = isoParameters.zkMetadata as? ZkMetadata.IsoMdocZk
            ?: throw IllegalArgumentException("ZK metadata incompatible with Iso mDoc!")

        val supportedBackends = findSupportedBackends(zkMetadata.zkInfo.systemSpecs)

        val (selectedBackend, supportedSystems) = selectionStrategy.selectForGenerate(supportedBackends)
            ?: throw PresentationException("No backend found for specified ZK systems!")

        selectedBackend.generate(
            request = request,
            credential = isoParameters.credential,
            requestedClaims = isoParameters.claims,
            zkSystems = supportedSystems
        ).getOrThrow()
    }

    /**
     * Assembles a verifiable [IsoMdocZkProof] from an existing [ZkDocument] and available [ZkSystem]s.
     */
    fun load(
        zkSystem: ZkSystem,
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
    ): KmmResult<IsoMdocZkProof> = catching {
        val zkSystemId = zkDocument.zkDocumentDataBytes.value.zkSystemId
        if (zkSystemId != zkSystem.zkSystemId)
            throw PresentationException("ZKSystemId mismatch")

        val matchingBackends = backends.load()
            .filter { it.supports(zkSystem) }
        val backend = selectionStrategy.selectForLoad(matchingBackends)
            ?: throw PresentationException("No backend found for ZK system: $zkSystemId")

        backend.load(zkDocument, sessionTranscript, zkSystem)
    }

    private fun findSupportedBackends(zkSystems: List<ZkSystem>): Map<IsoMdocZkBackend, List<ZkSystem>> =
        backends.load()
            .associateWith { backend -> zkSystems.filter { backend.supports(it) } }
            .filterValues { it.isNotEmpty() }

    companion object {
        val Default = IsoMdocZkBackendRegistry(SelectionStrategy.Default)
    }
}