package at.asitplus.wallet.lib.zk.iso

import at.asitplus.iso.ZkDocument
import at.asitplus.iso.ZkDocumentData
import at.asitplus.iso.ZkSignedList
import at.asitplus.iso.ZkSystem
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import kotlinx.datetime.LocalDate

/**
 * Intermediary representation of an ISO mDoc Zero-Knowledge proof.
 *
 * This class holds the generated proof and its associated metadata. It can be verified
 * or converted into a [ZkDocument] for inclusion in a presentation.
 *
 * It ensures that the [zkSystem] used for proof generation is available and tracked
 * alongside the proof data.
 */
abstract class IsoMdocZkProof protected constructor() {
    /**
     * The ZK system specification used to generate this proof.
     */
    abstract val zkSystem: ZkSystem

    /**
     * Map of issuer-signed namespaces included in the proof.
     */
    abstract val issuerZkSignedNamespaces: Map<String, ZkSignedList>

    /**
     * Map of device-signed namespaces included in the proof.
     */
    abstract val deviceZkSignedNamespaces: Map<String, ZkSignedList>

    /**
     * The raw byte representation of the ZK proof.
     */
    abstract val rawProof: ByteArray

    /**
     * The type of the document this proof is for (e.g., "org.iso.18013.5.1.mDL").
     */
    abstract val docType: String

    /**
     * The X.509 certificate chain used by the issuer for the Mobile Security Object (MSO), if available.
     */
    abstract val msoX5Chain: List<ByteArray>?

    /**
     * The timestamp of when the proof was generated or the relevant reference time.
     */
    abstract val timestamp: LocalDate

    /**
     * Verifies the ZK proof against the [zkSystem] and the provided data.
     *
     * @return `true` if the proof is valid, `false` otherwise.
     */
    abstract suspend fun verify(): Boolean

    /**
     * Converts this intermediate proof representation into a [ZkDocument],
     * which is the wire-format used in OpenID4VP presentations.
     */
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