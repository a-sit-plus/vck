package at.asitplus.iso.zk

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystemSpec
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlin.time.Instant

abstract class IsoMdocZkProof protected constructor() {
    abstract val zkSystemSpec: ZkSystemSpec
    abstract val issuerZkSignedNamespaces: Map<String, ZkSignedList>
    abstract val deviceZkSignedNamespaces: Map<String, ZkSignedList>
    abstract val rawProof: ByteArray
    abstract val docType: String
    abstract val msoX5Chain: List<ByteArray>?
    abstract val timestamp: Instant

    abstract fun verify(): Boolean

    fun toZkDocument(): ZkDocument = ZkDocument(
        zkDocumentDataBytes = ByteStringWrapper(
            ZkDocumentData(
                docType = docType,
                zkSystemId = zkSystemSpec.zkSystemId,
                timestamp = timestamp,
                issuerSigned = issuerZkSignedNamespaces,
                deviceSigned = deviceZkSignedNamespaces,
                certificateChain = msoX5Chain
            )
        ),
        proof = rawProof,
    )

}