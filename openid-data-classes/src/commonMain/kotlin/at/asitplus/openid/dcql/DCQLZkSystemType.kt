package at.asitplus.openid.dcql

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * ZK System Specification for Mdoc-Zk proofs
 * See: https://github.com/google/longfellow-zk/blob/main/docs/content/en/docs/zk-system-spec.md
 */
@Serializable
data class DCQLZkSystemType (
    @SerialName(PROP_ID)
    val id: String,

    @SerialName(PROP_SYSTEM)
    val system: String,

    @SerialName(PROP_CIRCUIT_HASH)
    val circuitHash: String,

    @SerialName(PROP_NUM_ATTRIBUTES)
    val numAttributes: Int,

    @SerialName(PROP_VERSION)
    val version: Int,

    @SerialName(PROP_BLOCK_ENC_HASH)
    val blockEncHash: Int? = null,

    @SerialName(PROP_BLOCK_ENC_SIG)
    val blockEncSig: Int? = null,
) {
    companion object {
        const val PROP_ID = "id"
        const val PROP_SYSTEM = "system"
        const val PROP_CIRCUIT_HASH = "circuit_hash"
        const val PROP_NUM_ATTRIBUTES = "num_attributes"
        const val PROP_VERSION = "version"
        const val PROP_BLOCK_ENC_HASH = "block_enc_hash"
        const val PROP_BLOCK_ENC_SIG = "block_enc_sig"
    }
}