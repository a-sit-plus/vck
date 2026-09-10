package at.asitplus.wallet.lib.zk.iso

import at.asitplus.KmmResult
import at.asitplus.iso.ZkDocument
/**
 * Intermediary self-contained representation of an ISO mDoc Zero-Knowledge proof.
 *
 * This class holds the generated proof and its associated metadata allowing it to be verifiable
 * without additional context
 */
class IsoMdocZkProof(
    val zkDocument: ZkDocument,
    private val verifyFn: suspend (ZkDocument) -> KmmResult<Unit>
) {
    /**
     * Verifies the ZK proof.
     *
     * This method is designed to be fully self-contained for the verifier. Automatically uses the correct
     * backend's verification logic requiring no manual routing by the caller.
     *
     * @return [KmmResult]-wrapped [Unit] if the proof is valid, or [Throwable] with the error if otherwise, e.g., if the
     * proof is invalid, the required ZK system is unsupported, or any other internal error occurs during evaluation.
     */
    suspend fun verify(): KmmResult<Unit> = verifyFn.invoke(zkDocument)

}