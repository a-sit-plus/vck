package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.agent.PresentationRequestParameters
import at.asitplus.wallet.lib.agent.SubjectCredentialStore

interface IsoMdocZkProofFactory {
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
}


