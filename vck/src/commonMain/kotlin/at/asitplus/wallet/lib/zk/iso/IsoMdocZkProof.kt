package at.asitplus.wallet.lib.zk.iso

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystem
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.datetime.LocalDate

abstract class IsoMdocZkProof protected constructor() {
    abstract val zkSystem: ZkSystem
    abstract val issuerZkSignedNamespaces: Map<String, ZkSignedList>
    abstract val deviceZkSignedNamespaces: Map<String, ZkSignedList>
    abstract val rawProof: ByteArray
    abstract val docType: String
    abstract val msoX5Chain: List<ByteArray>?
    abstract val timestamp: LocalDate

    abstract suspend fun verify(): Boolean

    fun toZkDocument(): ZkDocument = ZkDocument(
        zkDocumentDataBytes = ByteStringWrapper(
            ZkDocumentData(
                docType = docType,
                zkSystemId = zkSystem.zkSystemId,
                timestamp = timestamp,
                issuerSigned = issuerZkSignedNamespaces,
                deviceSigned = deviceZkSignedNamespaces,
                certificateChain = msoX5Chain
            )
        ),
        proof = rawProof,
    )

}