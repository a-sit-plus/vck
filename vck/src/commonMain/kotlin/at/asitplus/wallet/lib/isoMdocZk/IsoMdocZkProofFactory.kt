package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.SessionTranscript
import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkSystemSpec

interface IsoMdocZkProofFactory {
    fun supports(zkSystemSpec: ZkSystemSpec): Boolean

    // TODO: add support for creating an MdocZkProof from a request

    fun load(
        zkDocument: ZkDocument,
        sessionTranscript: SessionTranscript,
        zkSystemSpec: ZkSystemSpec
    ): IsoMdocZkProof
}


