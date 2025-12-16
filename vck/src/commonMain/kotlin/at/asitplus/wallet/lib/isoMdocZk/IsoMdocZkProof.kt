package at.asitplus.wallet.lib.isoMdocZk

import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystemSpec
import kotlin.time.Instant

abstract class IsoMdocZkProof {
    abstract val zkSystemSpec: ZkSystemSpec
    abstract val issuerSignedNamespaces: Map<String, ZkSignedList>
    abstract val deviceSignedNamespaces: Map<String, ZkSignedList>
    abstract val rawProof: ByteArray
    abstract val docType: String
    abstract val msoX5Chain: List<ByteArray>?
    abstract val timestamp: Instant

    abstract fun verify(): Boolean

}