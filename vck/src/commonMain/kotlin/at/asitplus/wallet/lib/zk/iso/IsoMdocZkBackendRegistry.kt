package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.ZkSystemParamRegistry
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.update

/**
 * Registry for managing available [IsoMdocZkBackend] instances.
 *
 * Registration is additive and permanent: once a backend is initialized and added to this registry,
 * it remains available and operational for the entire application lifecycle. This guarantees thread-safe,
 * consistent execution for concurrent or in-flight proof generation and loading operations without risk
 * of backend removal.
 */
@OptIn(ExperimentalAtomicApi::class)
class IsoMdocZkBackendRegistry {
    private val atomicBackends = AtomicReference<Set<IsoMdocZkBackend>>(emptySet())

    /**
     * An immutable snapshot of currently registered backends.
     *
     * Once registered, backends remain permanently active and operational in this set.
     * Safe to access from any thread at any time.
     */
    val backends: Set<IsoMdocZkBackend>
        get() = atomicBackends.load()

    /**
     * Registers an [IsoMdocZkBackend] for use in presentation generation and proof loading.
     *
     * Ensures the backend is successfully initialized and its system parameters are globally registered
     * with [ZkSystemParamRegistry] before committing it to the available pool.
     *
     * Multiple backends for the same [IsoMdocZkBackend.systemName] can be registered. This is useful if
     * different backends support different versions or configurations of the same ZK system.
     * However, their [IsoMdocZkBackend.paramSerializers] must be compatible; otherwise, an
     * [IllegalStateException] will be thrown during registration.
     *
     * Once registered, the backend remains operational and cannot be unregistered.
     */
    suspend fun register(backend: IsoMdocZkBackend): KmmResult<Unit> = catching {
        backend.initialize().getOrThrow()
        ZkSystemParamRegistry.register(backend.systemName, backend.paramSerializers)
        atomicBackends.update { it + backend }
    }

    companion object {
        /**
         * A shared [IsoMdocZkBackendRegistry] for use in standard application contexts.
         */
        val Default = IsoMdocZkBackendRegistry()
    }
}