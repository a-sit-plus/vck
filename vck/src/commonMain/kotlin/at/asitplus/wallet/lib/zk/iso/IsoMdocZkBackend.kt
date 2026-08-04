package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystem
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.KSerializer

interface IsoMdocZkBackend {
    val systemName: String
    val paramSerializers: Map<String, KSerializer<*>>

    fun supports(zkSystem: ZkSystem): Boolean

    suspend fun generate(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        zkSystems: List<ZkSystem>
    ): KmmResult<IsoMdocZkProof>

    fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystem: ZkSystem
    ): IsoMdocZkProof

    /**
     * [initialize] tries to register a backend and returns Unit if successful and a throwable otherwise.
     * Repeated calls for an already successfully initialized backend MUST succeed.
     */
    suspend fun initialize(): KmmResult<Unit>
}