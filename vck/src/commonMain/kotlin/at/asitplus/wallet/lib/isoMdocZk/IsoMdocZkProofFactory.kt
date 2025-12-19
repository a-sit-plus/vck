package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.KmmResult
import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore
import kotlinx.serialization.KSerializer

interface IsoMdocZkProofFactory {
    val systemName: String


    val paramSerializers: Map<String, KSerializer<*>>

    fun supports(zkSystemSpec: ZkSystemSpec): Boolean

    suspend fun generate(
        request: PresentationRequestParameters,
        credential: SubjectCredentialStore.StoreEntry.Iso,
        requestedClaims: Collection<NormalizedJsonPath>,
        zkSystemSpec: ZkSystemSpec
    ): IsoMdocZkProof

    fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): IsoMdocZkProof

    /**
     * [initialize] tries to register the factory and returns Unit if successful and a throwable otherwise
     * it may be called multiple times for the same factory
     */
    fun initialize(): KmmResult<Unit>
}